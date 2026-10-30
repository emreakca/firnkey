// UI strings live in _locales/<language>/messages.json; Chrome picks the browser's language and
// falls back to English. Values fill $1…$9 in the message.
export function t(key: string, ...values: (string | number)[]): string {
  return chrome.i18n.getMessage(key, values.map(String)) || key;
}

let rules: Intl.PluralRules | undefined;

// Counted messages have one key per plural form (`key_one`, `key_other`, and `key_few` or `key_many`
// where a language needs them). The count is $1, further values $2 onwards.
export function plural(key: string, count: number, ...values: (string | number)[]): string {
  rules ??= new Intl.PluralRules(t("languageCode"));
  const substitutions = [count, ...values].map(String);
  return chrome.i18n.getMessage(`${key}_${rules.select(count)}`, substitutions) || t(`${key}_other`, ...substitutions);
}

// Extension HTML is not localized by Chrome, so pages write __MSG_key__ in text and attributes.
export function localizePage(): void {
  const swap = (text: string) => text.replace(/__MSG_(\w+)__/g, (_, key: string) => t(key));
  const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (node.nodeValue?.includes("__MSG_")) node.nodeValue = swap(node.nodeValue);
  }
  for (const element of document.querySelectorAll("*")) {
    for (const attribute of element.attributes) if (attribute.value.includes("__MSG_")) attribute.value = swap(attribute.value);
  }
}
