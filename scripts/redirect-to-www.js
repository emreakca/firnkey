// Cloudflare Worker on firnkey.com: send every request to the same path on www.firnkey.com.
export default {
  fetch(request) {
    const url = new URL(request.url);
    url.protocol = "https:";
    url.hostname = "www.firnkey.com";
    return Response.redirect(url, 301);
  },
};
