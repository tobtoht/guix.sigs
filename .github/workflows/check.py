import gnupg
import os.path
import re
import subprocess


def fatal_error(message : str):
    print(message)
    exit(-1)


def check_attestations(attestations : list[str], builder_keys : set[str]):
    for att in attestations:
        gpg = gnupg.GPG()
        gpg.encoding = 'utf-8'

        builder = att.split('/')[1]
        builder_key = f"builder-keys/{builder}.asc"
        builder_keys.discard(builder_key)

        try:
            with open(builder_key) as f:
                builder_key_file = f.read()
        except FileNotFoundError as e:
            fatal_error(f"Builder key not found for attestation. Attestation: '{att}', Key: '{builder_key}', Error: '{e}'.\nHelp: Run 'gpg --export --armor {builder} > {builder_key} && git add {builder_key}'")

        if not builder_key_file.isascii():
            fatal_error("All files must be in ascii format. Make sure to pass --armor to gpg. File: {file}")

        import_result = gpg.import_keys(builder_key_file)

        if import_result.returncode != 0:
            fatal_error(f"Builder key not imported. Key: '{builder_key}', Error: '{import_result.results}'")

        if import_result.count != 1 or import_result.not_imported > 0:
            fatal_error(f"Too many or too few builder keys considered for import. Key: '{builder_key}', Considered: {import_result.count}, Not imported: {import_result.not_imported}")

        try:
            with open(att, 'rb') as f:
                attestation_data = f.read()
        except FileNotFoundError as e:
            fatal_error("File does not exist")

        verified = gpg.verify_data(f"{att}.asc", attestation_data)

        if not verified.valid:
            fatal_error(f"Signature does not verify. Attestation '{att}', Key: '{builder_key}', Error: '{verified.status}'")

        if len(verified.sig_info) != 1:
           fatal_error(f"Too many or too few signatures. Attestation: '{att}', Key: '{builder_key}, Sigs len: {len(verified.sig_info)})")

    if len(builder_keys) > 0:
        fatal_error(f"Added builder keys without new attestation. Extra keys: '{builder_keys}'")


def check_touched_files(touched_files : list[str]) -> (list[str], set[str]):
    attestations = {}
    builder_keys = set()

    for touched_file in touched_files:
        status, file = touched_file.split('\t')
        print(f"Touched file: {status} {file}")

        # Ignore changes to these files / paths
        if any(file.startswith(x) for x in ["README.md", "ERRATA.md", "contrib/", ".github/"]):
            continue

        attestation_pattern = R"^([^/]+/[^/]+/[^/]+.SHA256SUMS)(|.asc)$"
        is_attestion = re.match(attestation_pattern, file)
        if is_attestion:
            if status != "A":
                fatal_error(f"File status for attestation is not 'A' (for add): '{status}' '{file}")

            path = file.removesuffix(".asc")
            if path not in attestations:
                attestations[path] = list()

            attestations[path].append(os.path.basename(file))
            continue

        builder_key_pattern = "^(builder-keys/[^/]+.asc)$"
        is_builder_key = re.match(builder_key_pattern, file)
        if is_builder_key:
            if status not in ["A", "M"]:
                fatal_error(f"File status for builder key is not 'A' (for add) or 'M' (for modified): '{status}' '{file}'")
            builder_keys.add(file)
            continue

        fatal_error(f"Added unknown file: '{file}'")

    for path in attestations:
        files = attestations[path]
        if sorted(files) != ['noncodesigned.SHA256SUMS', 'noncodesigned.SHA256SUMS.asc']:
            fatal_error(f"Missing SHA256SUMS.asc or SHA256SUMS file in {path}")

    return attestations.keys(), builder_keys

if __name__ == "__main__":
    # Obtain a list of files that were added, modified or deleted in this commit
    result = subprocess.run(
        ["git", "diff", "--no-commit-id", "--name-status", "HEAD~..HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        fatal_error("unable to obtain list of changed files")

    touched_files = result.stdout.splitlines()
    attestations, builder_keys = check_touched_files(touched_files)

    check_attestations(attestations, builder_keys)
