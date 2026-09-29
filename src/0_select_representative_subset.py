"""
Seleciona um subconjunto representativo de capturas brutas.

O objetivo deste estágio é permitir desenvolvimento local sem processar o
dataset inteiro. A estratégia usada é:

1. estratificação por região AWS inferida do nome do arquivo;
2. alocação proporcional de amostras por região;
3. seleção sistemática dos arquivos ordenados por timestamp;
4. criação de um diretório de saída com links simbólicos ou cópias;
5. geração de um manifesto com o subconjunto escolhido.

Aplica-se a diretórios com capturas brutas na nomenclatura
<região><az>-<IP>-<data>-<hora> (ex.: a raiz de datasets/e3_raw). Os agregados
por região (ex.: datasets/e3_full/e3_<região>.pcap.gz) não são elegíveis — ver
contexto/dataset_e3.md.

Uso típico:

  python3 src/0_select_representative_subset.py datasets/e3_raw \
      --output datasets/e3_subset \
      --max-files 48

Depois disso, o diretório de saída pode ser processado pelo pipeline normal:

  python3 src/1_generate_tshark_csv.py datasets/e3_subset
  time zcat datasets/e3_subset/output.csv.gz | python src/2_enrich_csv.py \
      | gzip > datasets/e3_subset/output.enriched.csv.gz
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_MAX_FILES = 48
DEFAULT_MIN_PER_REGION = 1
SUPPORTED_EXTENSIONS = (".pcap.gz", ".pcap")


@dataclass(frozen=True)
class CaptureFile:
    source_path: Path
    region: str
    az: str
    ip: str
    captured_at: datetime


FILENAME_RE = re.compile(
    r"^(?P<region>.+?)[-_](?P<ip>(?:\d{1,3}\.){3}\d{1,3})[-_](?P<date>\d{4}[-−]?\d{2}[-−]?\d{2}|\d{8})[-_](?P<time>\d{2}[-:]?\d{2}(?:[-:]?\d{2})?)$"
)

# O nome do arquivo concatena a letra do AZ diretamente ao dígito da região,
# sem separador (ex: "af-south-1b" = região "af-south-1" + AZ "b"). Sem esta
# separação, a regex acima trata região+AZ como uma única unidade de
# estratificação, inflando o número de estratos além das 26 regiões AWS
# declaradas na metodologia (Objetivo 3).
REGION_AZ_RE = re.compile(r"^(?P<base_region>.+-\d+)(?P<az>[a-z])$")


def normalize_filename(filename: str) -> str:
    return filename.replace("−", "-")


def parse_capture_file(path: Path) -> CaptureFile | None:
    name = normalize_filename(path.name)

    for suffix in (".pcap.gz", ".pcap.txt", ".pcap"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break

    match = FILENAME_RE.match(name)
    if not match:
        return None

    region = match.group("region")
    az_match = REGION_AZ_RE.match(region)
    if az_match:
        region, az = az_match.group("base_region"), az_match.group("az")
    else:
        az = ""

    ip = match.group("ip")
    date_text = match.group("date").replace("−", "-").replace("-", "")
    time_text = match.group("time").replace(":", "").replace("-", "")

    try:
        date_part = datetime.strptime(date_text, "%Y%m%d")
    except ValueError:
        return None

    if len(time_text) == 4:
        time_format = "%H%M"
    elif len(time_text) == 6:
        time_format = "%H%M%S"
    else:
        return None

    try:
        time_part = datetime.strptime(time_text, time_format)
    except ValueError:
        return None

    captured_at = datetime.combine(date_part.date(), time_part.time())
    return CaptureFile(source_path=path, region=region, az=az, ip=ip, captured_at=captured_at)


def list_candidate_files(dataset_dir: Path) -> list[CaptureFile]:
    captures: list[CaptureFile] = []
    for path in sorted(dataset_dir.iterdir()):
        if not path.is_file():
            continue
        if not any(path.name.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
            continue

        capture = parse_capture_file(path)
        if capture is None:
            continue
        captures.append(capture)

    return captures


def allocate_quotas(
    grouped: dict[str, list[CaptureFile]],
    max_files: int,
    min_per_region: int,
) -> dict[str, int]:
    regions = sorted(grouped)
    total_files = sum(len(files) for files in grouped.values())

    if total_files <= max_files:
        return {region: len(grouped[region]) for region in regions}

    quota = {region: min(min_per_region, len(grouped[region])) for region in regions}
    remaining = max_files - sum(quota.values())

    if remaining <= 0:
        return quota

    weights = {region: len(grouped[region]) / total_files for region in regions}
    fractional: list[tuple[float, str]] = []

    for region in regions:
        capacity = len(grouped[region]) - quota[region]
        if capacity <= 0:
            continue
        desired = remaining * weights[region]
        extra = min(capacity, math.floor(desired))
        quota[region] += extra
        remaining -= extra
        fractional.append((desired - math.floor(desired), region))

    if remaining > 0:
        for _, region in sorted(fractional, reverse=True):
            if remaining <= 0:
                break
            capacity = len(grouped[region]) - quota[region]
            if capacity <= 0:
                continue
            quota[region] += 1
            remaining -= 1

    if remaining > 0:
        for region in regions:
            if remaining <= 0:
                break
            capacity = len(grouped[region]) - quota[region]
            if capacity <= 0:
                continue
            take = min(capacity, remaining)
            quota[region] += take
            remaining -= take

    return quota


def pick_evenly_spaced(files: list[CaptureFile], quota: int) -> list[CaptureFile]:
    if quota >= len(files):
        return files[:]

    if quota <= 1:
        return [files[len(files) // 2]]

    selected_indexes = []
    last_index = len(files) - 1
    for i in range(quota):
        position = round(i * last_index / (quota - 1))
        selected_indexes.append(position)

    # Garante que não haja duplicatas quando a amostra é muito pequena.
    deduplicated: list[int] = []
    seen: set[int] = set()
    for index in selected_indexes:
        if index not in seen:
            seen.add(index)
            deduplicated.append(index)

    while len(deduplicated) < quota:
        for index in range(len(files)):
            if index not in seen:
                seen.add(index)
                deduplicated.append(index)
                if len(deduplicated) == quota:
                    break

    return [files[index] for index in deduplicated[:quota]]


def make_output_dir(output_dir: Path, clean: bool) -> None:
    if output_dir.exists():
        if clean:
            shutil.rmtree(output_dir)
        elif any(output_dir.iterdir()):
            raise SystemExit(
                f"Diretório de saída já existe e não está vazio: {output_dir}. "
                "Use --clean para recriá-lo."
            )

    output_dir.mkdir(parents=True, exist_ok=True)


def materialize_selection(
    selected: list[CaptureFile],
    output_dir: Path,
    copy_files: bool,
) -> None:
    for capture in selected:
        destination = output_dir / capture.source_path.name
        if destination.exists() or destination.is_symlink():
            destination.unlink()

        if copy_files:
            shutil.copy2(capture.source_path, destination)
        else:
            destination.symlink_to(capture.source_path.resolve())


def write_manifest(selected: list[CaptureFile], output_dir: Path, quotas: dict[str, int]) -> None:
    manifest_csv = output_dir / "subset_manifest.csv"
    manifest_json = output_dir / "subset_manifest.json"

    with manifest_csv.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "region",
                "az",
                "ip",
                "captured_at",
                "source_file",
                "source_path",
                "size_bytes",
            ],
        )
        writer.writeheader()
        for capture in selected:
            writer.writerow(
                {
                    "region": capture.region,
                    "az": capture.az,
                    "ip": capture.ip,
                    "captured_at": capture.captured_at.isoformat(sep=" "),
                    "source_file": capture.source_path.name,
                    "source_path": str(capture.source_path),
                    "size_bytes": capture.source_path.stat().st_size,
                }
            )

    summary = {
        "selected_files": len(selected),
        "regions": len(quotas),
        "quotas_by_region": quotas,
        "captured_period": {
            "first": min((capture.captured_at for capture in selected), default=None),
            "last": max((capture.captured_at for capture in selected), default=None),
        },
    }

    with manifest_json.open("w", encoding="utf-8") as json_file:
        json.dump(summary, json_file, indent=2, ensure_ascii=False, default=str)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seleciona um subconjunto representativo de capturas brutas (nomenclatura <região><az>-<IP>-<data>-<hora>).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("dataset_dir", help="Diretório com os arquivos de captura .pcap.gz")
    parser.add_argument(
        "--output",
        required=True,
        help="Diretório de saída para o subconjunto selecionado",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help="Número máximo de arquivos a selecionar",
    )
    parser.add_argument(
        "--min-per-region",
        type=int,
        default=DEFAULT_MIN_PER_REGION,
        help="Número mínimo de arquivos por região, quando possível",
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="Copia os arquivos em vez de criar links simbólicos",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Recria o diretório de saída antes de materializar o subconjunto",
    )

    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir).expanduser().resolve()
    output_dir = Path(args.output).expanduser().resolve()

    if not dataset_dir.exists():
        raise SystemExit(f"Diretório do dataset não encontrado: {dataset_dir}")

    if args.max_files <= 0:
        raise SystemExit("--max-files deve ser maior que zero")

    if args.min_per_region <= 0:
        raise SystemExit("--min-per-region deve ser maior que zero")

    captures = list_candidate_files(dataset_dir)
    if not captures:
        raise SystemExit(
            "Nenhum arquivo de captura compatível foi encontrado. "
            "Verifique se o dataset contém arquivos .pcap.gz com o padrão esperado."
        )

    grouped: dict[str, list[CaptureFile]] = defaultdict(list)
    for capture in captures:
        grouped[capture.region].append(capture)

    for region in grouped:
        grouped[region].sort(key=lambda item: (item.captured_at, item.source_path.name))

    quotas = allocate_quotas(grouped, args.max_files, args.min_per_region)

    selected: list[CaptureFile] = []
    for region in sorted(grouped):
        selected.extend(pick_evenly_spaced(grouped[region], quotas.get(region, 0)))

    selected.sort(key=lambda item: (item.region, item.captured_at, item.source_path.name))

    make_output_dir(output_dir, args.clean)
    materialize_selection(selected, output_dir, args.copy)
    write_manifest(selected, output_dir, quotas)

    total_size = sum(capture.source_path.stat().st_size for capture in selected)
    print(f"Arquivos elegíveis encontrados: {len(captures)}")
    print(f"Arquivos selecionados: {len(selected)}")
    print(f"Tamanho aproximado selecionado: {total_size} bytes")
    print(f"Diretório de saída: {output_dir}")
    print(f"Manifestos gerados: {output_dir / 'subset_manifest.csv'} e {output_dir / 'subset_manifest.json'}")


if __name__ == "__main__":
    main()
