function remarksOf(server) {
  return String(server.remarks || "");
}

function isLte(server) {
  return remarksOf(server).indexOf("LTE") !== -1;
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
  }

  return { body: JSON.stringify(out), headers: response_headers };
};
