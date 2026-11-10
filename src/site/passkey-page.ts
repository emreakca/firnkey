// Runs in the page's own JavaScript world (top frame). It forwards WebAuthn calls to Firnkey's
// isolated bridge and turns the answers back into credential objects. It holds no secrets: the page
// already sees every value that passes through here.
import type { PasskeyPageResult } from "../shared/messages";
import type { AssertedCredential, CreatedCredential } from "../passkey/webauthn";

(() => {
  const credentials = navigator.credentials;
  if (!credentials || typeof PublicKeyCredential === "undefined") return;
  const nativeCreate = credentials.create.bind(credentials);
  const nativeGet = credentials.get.bind(credentials);
  let nextId = 0;

  credentials.create = async (options?: CredentialCreationOptions) => {
    const publicKey = options?.publicKey;
    // Requests for a security key specifically go to the browser.
    if (!publicKey || options.signal?.aborted || publicKey.authenticatorSelection?.authenticatorAttachment === "cross-platform") {
      return nativeCreate(options);
    }
    const result = await ask("create", {
      challenge: encode(publicKey.challenge),
      rpId: publicKey.rp.id,
      rpName: publicKey.rp.name,
      userId: encode(publicKey.user.id),
      userName: publicKey.user.name,
      userDisplayName: publicKey.user.displayName,
      algorithms: publicKey.pubKeyCredParams.map((parameter) => parameter.alg),
      excludeCredentials: (publicKey.excludeCredentials ?? []).map((credential) => encode(credential.id)),
      userVerification: publicKey.authenticatorSelection?.userVerification,
    }, options.signal);
    if ("fallback" in result) return nativeCreate(options);
    if ("error" in result) throw new DOMException("The operation either timed out or was not allowed.", result.error);
    if (!("created" in result)) throw new DOMException("Firnkey returned an unexpected answer.", "UnknownError");
    return created(result.created, Boolean(publicKey.extensions?.credProps));
  };

  credentials.get = async (options?: CredentialRequestOptions) => {
    const publicKey = options?.publicKey;
    if (!publicKey || options.signal?.aborted) return nativeGet(options);
    const request = {
      challenge: encode(publicKey.challenge),
      rpId: publicKey.rpId,
      allowCredentials: (publicKey.allowCredentials ?? []).map((credential) => encode(credential.id)),
      userVerification: publicKey.userVerification,
    };
    if (options.mediation === "conditional") return conditionalGet(options, request);
    const result = await ask("get", request, options.signal);
    if ("fallback" in result) return nativeGet(options);
    if ("error" in result) throw new DOMException("The operation either timed out or was not allowed.", result.error);
    if (!("asserted" in result)) throw new DOMException("Firnkey returned an unexpected answer.", "UnknownError");
    return asserted(result.asserted);
  };

  // Autofill sign-in: the browser keeps offering its own passkeys while Firnkey offers its ones in its
  // field menu. Whichever the user picks answers the page, and the other offer is withdrawn.
  async function conditionalGet(options: CredentialRequestOptions, request: object): Promise<Credential | null> {
    const pageSignal = options.signal;
    const linked = (own: AbortController) => (pageSignal ? AbortSignal.any([pageSignal, own.signal]) : own.signal);
    const browser = new AbortController();
    const firnkey = new AbortController();
    const fromBrowser = nativeGet({ ...options, signal: linked(browser) });
    const fromFirnkey = ask("get", { ...request, conditional: true }, linked(firnkey)).then((result) => {
      if (!("asserted" in result)) return fromBrowser; // Firnkey stepped aside; the browser's offer stands.
      browser.abort();
      return asserted(result.asserted);
    });
    try {
      return await Promise.race([fromBrowser, fromFirnkey]);
    } finally {
      browser.abort();
      firnkey.abort();
    }
  }

  function ask(kind: "create" | "get", options: unknown, signal?: AbortSignal | null): Promise<PasskeyPageResult> {
    const id = `${Date.now()}.${nextId++}`;
    return new Promise((resolve, reject) => {
      const onMessage = (event: MessageEvent) => {
        const data = event.data as { firnkey?: string; id?: string; result?: PasskeyPageResult } | null;
        if (event.source !== window || data?.firnkey !== "passkey-response" || data.id !== id || !data.result) return;
        done();
        resolve(data.result);
      };
      // An aborted request also closes Firnkey's window for it.
      const onAbort = () => {
        done();
        window.postMessage({ firnkey: "passkey-abort", id }, location.origin);
        reject(signal!.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      };
      const done = () => {
        window.removeEventListener("message", onMessage);
        signal?.removeEventListener("abort", onAbort);
      };
      window.addEventListener("message", onMessage);
      signal?.addEventListener("abort", onAbort, { once: true });
      window.postMessage({ firnkey: "passkey-request", id, kind, options }, location.origin);
    });
  }

  function created(value: CreatedCredential, credProps: boolean): PublicKeyCredential {
    const response = {
      clientDataJSON: decode(value.clientDataJSON),
      attestationObject: decode(value.attestationObject),
      getTransports: () => [...value.transports],
      getAuthenticatorData: () => decode(value.authenticatorData),
      getPublicKey: () => decode(value.publicKey),
      getPublicKeyAlgorithm: () => value.publicKeyAlgorithm,
    };
    return credential(value.id, response, AuthenticatorAttestationResponse.prototype, credProps ? { credProps: { rk: true } } : {}, {
      clientDataJSON: value.clientDataJSON,
      attestationObject: value.attestationObject,
      authenticatorData: value.authenticatorData,
      publicKey: value.publicKey,
      publicKeyAlgorithm: value.publicKeyAlgorithm,
      transports: value.transports,
    });
  }

  function asserted(value: AssertedCredential): PublicKeyCredential {
    const response = {
      clientDataJSON: decode(value.clientDataJSON),
      authenticatorData: decode(value.authenticatorData),
      signature: decode(value.signature),
      userHandle: value.userHandle ? decode(value.userHandle) : null,
    };
    return credential(value.id, response, AuthenticatorAssertionResponse.prototype, {}, {
      clientDataJSON: value.clientDataJSON,
      authenticatorData: value.authenticatorData,
      signature: value.signature,
      ...(value.userHandle ? { userHandle: value.userHandle } : {}),
    });
  }

  // Plain objects with the real prototypes, so `instanceof PublicKeyCredential` checks pass.
  function credential(id: string, response: object, prototype: object, extensions: object, responseJson: object): PublicKeyCredential {
    Object.setPrototypeOf(response, prototype);
    const result = {
      id,
      rawId: decode(id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => extensions,
      toJSON: () => ({ id, rawId: id, type: "public-key", authenticatorAttachment: "platform", clientExtensionResults: extensions, response: responseJson }),
    };
    Object.setPrototypeOf(result, PublicKeyCredential.prototype);
    return result as unknown as PublicKeyCredential;
  }

  function encode(source: BufferSource): string {
    const bytes = source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decode(value: string): ArrayBuffer {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes.buffer;
  }
})();
