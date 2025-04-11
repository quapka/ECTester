#!/usr/bin/env python3

import subprocess as sp

import argparse
import json
import yaml
import tempfile
import re


from collections import defaultdict
from pathlib import Path
from typing import Final, List

import pandas as pd


TEST_SUITES: Final[List[str]] = [
    "default",
    "test-vectors",
    "performance",
    "signature",
    "miscellaneous",
    "invalid",
    "twist",
    "degenerate",
    "edge-cases",
    "cofactor",
    "composite",
    "wrong",
]


def get_all_versions(library):
    with open(f"./nix/{library}_pkg_versions.json", "r") as handle:
        versions = json.load(handle)
    return versions


def preamble():
    return r"""
\documentclass[preview, border={1cm 1cm 16cm 1cm}]{standalone}

\usepackage{fontawesome}
\usepackage{xcolor}
\usepackage{booktabs}

% typesetting of _ in text as \_
\usepackage{lmodern}
\usepackage[T1]{fontenc}
\usepackage{textcomp}

\begin{document}
""".strip().split(
        "\n"
    )


def footer():
    return """
\end{document}
""".strip().split(
        "\n"
    )


def build_results_to_latex(library):
    versions = get_all_versions(library)
    lib_results = get_results(library, "lib")

    lib_rows = [
        (
            r"{\color{blue}\faCheck}"
            if lib_results[ver]["success"]
            else r"{\color{red}\faRemove}"
        )
        for ver in versions.keys()
    ]

    shim_results = get_results(library, "shim")
    shim_rows = [
        (
            r"{\color{blue}\faCheck}"
            if shim_results[ver]["success"]
            else r"{\color{red}\faRemove}"
        )
        for ver in versions.keys()
    ]
    # shim_rows = [shim_results[ver] for ver in versions.keys()]

    cleaned_versions = [v.replace("_", r"{\_}") for v in versions.keys()]
    df = pd.DataFrame(dict(Versions=cleaned_versions, Library=lib_rows, Shim=shim_rows))
    # FIXME there should be a translation from `openssl` -> `OpenSSL` etc.
    tabledir = Path(f"./build_all/tables")
    tabledir.mkdir(parents=True, exist_ok=True)
    with open(tabledir / f"{library}.tex", "w") as handle:
        handle.write(
            df.to_latex(
                index=False, caption=library, label=f"{library}-lib-and-shim-builds"
            )
        )


def table_header_lines():
    suites_header = " & ".join(suite for suite in TEST_SUITES)
    return f"""
\\begin{{table}}
    \\centering
	\\begin{{tabular}}{{lll|llllllllllll}}
		\\toprule
		Versions & Library & Shim & {suites_header} \\\\
		\\midrule
""".strip().split(
        "\n"
    )


def table_footer_lines(library):
    return f"""
		\\bottomrule
	\\end{{tabular}}
	\\caption{{{library} \\label{{{library}-lib-and-shim-builds}} }}
\\end{{table}}
""".strip().split(
        "\n"
    )


def get_results_rows(library):
    versions = get_all_versions(library)
    lib_results = get_results(library, "lib")
    shim_results = get_results(library, "shim")

    results_dir = Path("./results/yml")
    rows = []
    for ver, values in versions.items():
        print(f"\tversion: {ver}")
        # row = {}
        # For most libraries we can reference a particular version
        try:
            identifier = values["version"].replace("_", r"{\_}")
            if "do_not_use" in ver:
                identifier += "{\_}do{\_}not{\_}use"
        # Otherwise we keep the `ver` which is likely an abbreviated commit
        except KeyError:
            identifier = ver

        row = {
            "identifier": identifier,
            "library": lib_results[ver]["success"],
            "shim": shim_results[ver]["success"],
        }

        for suite in TEST_SUITES:
            print(f"\t\tsuite: {suite}")
            ok = False
            try:
                with open(results_dir / f"{library}_{suite}_{ver}.yml", "r") as handle:
                    try:
                        ok = (
                            True
                            if re.search(
                                "\s+ok:\s+(?P<res>true|false)", handle.read()
                            ).group("res")
                            == "true"
                            else False
                        )
                    except Exception:
                        ok = False
            except FileNotFoundError:
                ok = False
                # try:
                # NOTE we expect to have all results for now
                # for event in yaml.parse(handle):
                #     print(event)
                # # data = yaml.safe_load("\n".join(handle.readlines(100)))
                # ok = data["testRun"]["tests"][0]["result"]["ok"]
                # except yam.YAMLError:
            row[suite] = r"{\color{blue}\faCheck}" if ok else r"{\color{red}\faRemove}"
        rows.append(row)

    return rows


def create_latex_table(library):
    out = table_header_lines()
    for row in get_results_rows(library):
        good = r"{\color{blue}\faCheck}"
        bad = r"{\color{red}\faRemove}"

        mono_id = f"\\texttt{{{row['identifier']}}}"
        lib = good if row["library"] else bad
        shim = good if row["shim"] else bad

        suites_results = " & ".join(row[suite] for suite in TEST_SUITES)
        tline = f"{mono_id} & {lib} & {shim} & {suites_results} \\\\"

        out.append(tline)

    out.extend(table_footer_lines(library))

    return out


def get_results(library, variant):
    with open(f"./build_all/{variant}/{library}.json", "r") as handle:
        return json.load(handle)


def create_standalone_latex_table(library):
    lines = preamble()
    lines.extend(create_latex_table(library))
    lines.extend(footer())

    standalone_dir = Path(f"./build_all/tables/standalone/")
    standalone_dir.mkdir(parents=True, exist_ok=True)

    # with NamedTemporaryFile(mode="w", delete_on_close=False) as tmp_handle:
    #     tmp_handle.writelines(lines)

    with open(standalone_dir / f"{library}.tex", "w") as handle:
        handle.write("\n".join(lines))
        # handle.writelines(lines)

    # indent the texfile
    sp.check_output(
        ["latexindent", "--overwrite", f"./{library}.tex"], cwd=standalone_dir
    )
    try:
        sp.check_output(
            ["pdflatex", "-interaction=nonstopmode", f"./{library}.tex"],
            cwd=standalone_dir,
        )
    except sp.CalledProcessError:
        print(f"Error typesseting: {library}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--library")
    # parser.add_argument("-v", "--variant", default="shim", type=valid_build_type)
    args = parser.parse_args()
    library = args.library
    # variant = args.variant

    libraries = [
        "botan",
        "cryptopp",
        "openssl",
        "boringssl",
        "gcrypt",
        "mbedtls",
        "ippcp",
        "nettle",
        "libressl",
    ]

    match library:
        case None:
            # print("Building all libraries")
            # # Build all libraries by default
            for lib in libraries:
                print(f"Processing: {lib}")
                # build_results_to_latex(lib)
                create_standalone_latex_table(lib)
            #     print(f"Library: {lib}")
            #     for version in get_all_versions(lib):
            #         result = attempt_build(lib, version, variant)
            #         save_build_result(lib, variant, version, result)
            #         print(f"{version}: {result['success']}")
        case lib if lib in libraries:
            print(f"Processing: {lib}")
            create_standalone_latex_table(lib)
            # build_results_to_latex(lib)
            # print(f"Library: {library}")
            # for version in get_all_versions(library):
            #     result = attempt_build(lib, version, variant)
            #     save_build_result(lib, variant, version, result)
            #     print(f"{version}: {result['success']}")
        case _:
            pass
            print(
                f"Unrecognized library '{library}'. Try one of: {', '.join(libraries)}."
            )


if __name__ == "__main__":
    main()
