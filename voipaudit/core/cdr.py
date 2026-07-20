"""
Asterisk CDR (Call Detail Record) CSV parsing.

Field order and format confirmed against Asterisk's own documentation
and cdr_csv.c source (github.com/asterisk/asterisk/blob/master/cdr/cdr_csv.c):

    accountcode,src,dst,dcontext,clid,channel,dstchannel,lastapp,
    lastdata,start,answer,end,duration,billsec,disposition,
    amaflags[,uniqueid][,userfield]

16 base fields; uniqueid and userfield are both optional per Asterisk's
own cdr.conf documentation, so a real Master.csv may have 16 or 18
columns depending on configuration — both are handled here, not just
the field count this module happened to be developed against.

`answer` is commonly empty for a call that was never answered (BUSY,
NO ANSWER, FAILED dispositions) — confirmed against a real sample row
from Asterisk's own community documentation, not assumed.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

_ASTERISK_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class CDRParseError(ValueError):
    """Raised when a CDR file doesn't match the expected Asterisk CSV
    shape — a wrong field count, or a start/end timestamp that doesn't
    parse. Never silently skips a malformed row and continues as if
    nothing were wrong; toll-fraud analysis is exactly the kind of
    thing where silently dropping rows could hide the calls that
    matter most."""


@dataclass
class CDRRecord:
    accountcode: str
    src: str
    dst: str
    dcontext: str
    clid: str
    channel: str
    dstchannel: str
    lastapp: str
    lastdata: str
    start: datetime
    answer: datetime | None
    end: datetime
    duration: int
    billsec: int
    disposition: str
    amaflags: str
    uniqueid: str = ""
    userfield: str = ""

    @property
    def answered(self) -> bool:
        return self.disposition.upper() == "ANSWERED"


def _parse_datetime(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, _ASTERISK_DATETIME_FORMAT)
    except ValueError as exc:
        raise CDRParseError(f"Unparseable timestamp {value!r} (expected 'YYYY-MM-DD HH:MM:SS')") from exc


def parse_asterisk_cdr_csv(path: str | Path) -> list[CDRRecord]:
    """Parses a real Asterisk Master.csv (or any cdr_csv-produced file)
    into a list of CDRRecord. Raises CDRParseError on the first
    malformed row rather than silently skipping it — see CDRParseError's
    own docstring for why that matters specifically for fraud analysis."""
    path = Path(path)
    if not path.exists():
        raise CDRParseError(f"CDR file not found: {path}")

    records: list[CDRRecord] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for line_num, row in enumerate(reader, start=1):
            if not row or all(not cell.strip() for cell in row):
                continue  # skip genuinely blank lines, not malformed data
            if len(row) not in (16, 17, 18):
                raise CDRParseError(
                    f"Line {line_num}: expected 16-18 fields (accountcode..amaflags, "
                    f"optionally uniqueid, userfield), got {len(row)}: {row!r}"
                )

            (
                accountcode, src, dst, dcontext, clid, channel, dstchannel,
                lastapp, lastdata, start_s, answer_s, end_s,
                duration_s, billsec_s, disposition, amaflags,
            ) = row[:16]
            uniqueid = row[16] if len(row) >= 17 else ""
            userfield = row[17] if len(row) >= 18 else ""

            try:
                start = _parse_datetime(start_s)
                if start is None:
                    raise CDRParseError(f"Line {line_num}: 'start' timestamp is empty — every real CDR row has one")
                end = _parse_datetime(end_s)
                if end is None:
                    raise CDRParseError(f"Line {line_num}: 'end' timestamp is empty — every real CDR row has one")
                answer = _parse_datetime(answer_s)  # legitimately empty for unanswered calls
            except CDRParseError as exc:
                raise CDRParseError(f"Line {line_num}: {exc}") from exc

            try:
                duration = int(duration_s)
                billsec = int(billsec_s)
            except ValueError as exc:
                raise CDRParseError(f"Line {line_num}: duration/billsec must be integers: {exc}") from exc

            records.append(CDRRecord(
                accountcode=accountcode, src=src, dst=dst, dcontext=dcontext, clid=clid,
                channel=channel, dstchannel=dstchannel, lastapp=lastapp, lastdata=lastdata,
                start=start, answer=answer, end=end, duration=duration, billsec=billsec,
                disposition=disposition, amaflags=amaflags, uniqueid=uniqueid, userfield=userfield,
            ))

    return records
