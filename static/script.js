
const form = document.getElementById("certificate-form");
const submitButton = document.getElementById("submit-button");
const message = document.getElementById("message");
const results = document.getElementById("results");

function showMessage(text, type = "") {
    message.textContent = text;
    message.className = `message ${type}`.trim();
}

function setCheck(name, result) {
    const statusElement = document.getElementById(`${name}-status`);
    const detailsElement = document.getElementById(`${name}-details`);

    statusElement.textContent = result.status;
    statusElement.className = `status-${result.status.toLowerCase().replaceAll(" ", "-")}`;
    detailsElement.textContent = result.details;
}

function addDetail(list, label, value) {
    const term = document.createElement("dt");
    term.textContent = label;

    const description = document.createElement("dd");
    description.textContent = value ?? "Not available";

    list.append(term, description);
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    results.classList.add("hidden");
    showMessage("Analyzing certificate…");
    submitButton.disabled = true;
    submitButton.textContent = "Analyzing…";

    try {
        const response = await fetch("/api/validate", {
            method: "POST",
            body: new FormData(form),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Certificate analysis failed.");
        }

        const report = data.report;
        const checks = report.validation;

        setCheck("signature", checks.signature);
        setCheck("hostname", checks.hostname);
        setCheck("chain", checks.chain);

        const banner = document.getElementById("status-banner");
        banner.className = `status-banner ${
            report.overall_status === "PASSED" ? "passed" : "failed"
        }`;
        banner.textContent =
            `Overall result: ${report.overall_status}. ` +
            `Validity: ${report.validity_status}.`;

        document.getElementById("result-title").textContent = report.file;

        const details = document.getElementById("certificate-details");
        details.replaceChildren();

        addDetail(details, "Subject", report.subject);
        addDetail(details, "Issuer", report.issuer);
        addDetail(details, "Version", report.version);
        addDetail(details, "Serial number", report.serial_number);
        addDetail(details, "Valid from", report.valid_from);
        addDetail(details, "Valid until", report.valid_until);
        addDetail(details, "Validity", report.validity_status);
        addDetail(details, "Public key", report.public_key.algorithm);
        addDetail(
            details,
            "Key size",
            report.public_key.key_size
                ? `${report.public_key.key_size} bits`
                : "Not applicable"
        );
        addDetail(details, "Signature algorithm", report.signature_algorithm);
        addDetail(details, "Signature hash", report.signature_hash);

        const san = document.getElementById("san-details");
        san.replaceChildren();

        const dnsText = report.subject_alternative_names.dns;
        const ipText = report.subject_alternative_names.ip_addresses;

        const sanLines = [
            ...dnsText.map((name) => `DNS: ${name}`),
            ...ipText.map((address) => `IP: ${address}`),
        ];

        san.textContent = sanLines.length
            ? sanLines.join(" · ")
            : "No DNS or IP SAN entries found.";

        document.getElementById("download-link").href = data.download_url;

        results.classList.remove("hidden");
        showMessage("Certificate analysis finished.", "success");
        results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        showMessage(error.message || "Unable to contact the local server.", "error");
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = 'Analyze certificate <span>→</span>';
    }
});
