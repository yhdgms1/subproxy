const BLOCK_SITES = ["geosite:win-spy", "geosite:category-ads-all"];

const RU_SITES = [
  "geosite:private",
  "geosite:category-ru",
  "geosite:category-gov-ru",
  "geosite:category-bank-ru",
  "geosite:category-ecommerce-ru",
  "geosite:category-media-ru",
  "geosite:tld-ru",
  "geosite:ru-available-only-inside",
  "geosite:yandex",
  "geosite:vk",
  "geosite:mailru",
  "geosite:mailru-group",
  "geosite:ok",
  "geosite:avito",
  "geosite:ozon",
  "geosite:wildberries",
  "geosite:2gis",
  "geosite:sber",
  "geosite:tbank-ru",
  "geosite:x5",
  "geosite:rutube",
  "geosite:dzen",
  "geosite:okko",
  "geosite:wink",
  "geosite:kinopoisk",
  "geosite:habr",
];

const RU_IP = [
  "geoip:private",
  "geoip:ru",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "224.0.0.0/4",
  "255.255.255.255/32",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
];

function remarksOf(server) {
  return String(server.remarks || "");
}

function isLte(server) {
  return remarksOf(server).indexOf("LTE") !== -1;
}

function directDns() {
  return {
    servers: [
      "https://1.1.1.1/dns-query",
      {
        address: "8.8.8.8",
        domains: RU_SITES,
        tag: "domestic_dns",
        skipFallback: true,
      },
    ],
    queryStrategy: "UseIP",
    hosts: {
      "one.one.one.one": "1.1.1.1",
      "dns.google": "8.8.8.8",
      "geosite:win-spy": "127.0.0.1",
      "geosite:category-ads-all": "127.0.0.1",
    },
  };
}

function withDirectRouting(server) {
  const clone = JSON.parse(JSON.stringify(server));
  const routing = clone.routing || {};
  const previous = routing.rules || [];
  const fallback = [];

  for (let i = 0; i < previous.length; i++) {
    if (previous[i].balancerTag) {
      fallback.push(previous[i]);
    }
  }

  routing.rules = [
    { type: "field", domain: BLOCK_SITES, outboundTag: "block" },
    { type: "field", domain: RU_SITES, outboundTag: "direct" },
    { type: "field", ip: RU_IP, outboundTag: "direct" },
  ].concat(fallback);

  routing.domainStrategy = "IPIfNonMatch";
  routing.domainMatcher = "hybrid";

  clone.routing = routing;
  clone.dns = directDns();
  clone.remarks = remarksOf(server) + ' | Direct';

  if (!clone.meta) {
    clone.meta = {};
  }

  clone.meta.serverDescription = '';

  const inbounds = clone.inbounds || [];
  for (let i = 0; i < inbounds.length; i++) {
    if (inbounds[i].sniffing) {
      inbounds[i].sniffing.enabled = true;
      inbounds[i].sniffing.routeOnly = true;
      inbounds[i].sniffing.destOverride = ["http", "tls", "quic"];
    }
  }

  return clone;
}

export const handle = async (response_body, response_headers) => {
  const list = typeof response_body === "string" ? JSON.parse(response_body) : response_body;
  const out = [];

  for (let i = 0; i < list.length; i++) {
    const server = list[i];
    if (isLte(server)) {
      continue;
    }

    out.push(server);
    out.push(withDirectRouting(server));
  }

  return { body: JSON.stringify(out), headers: response_headers };
};
