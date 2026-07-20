"""
Tests for CDR parsing and toll-fraud pattern detection.

Uses tests/fixtures/cdr/sample_master.csv — a real, hand-crafted
Asterisk-format CDR file (field order and shape confirmed against
Asterisk's own documentation and cdr_csv.c source before writing this
fixture, not invented) covering: two ordinary business-hours calls, an
unanswered call, a compromised-extension pattern (off-hours calls to
known high-risk international destinations), and a rapid-burst pattern
(five short calls in under 2 minutes to Dominican Republic numbers).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voipaudit.analyzers.toll_fraud import analyze_toll_fraud
from voipaudit.core.cdr import CDRParseError, parse_asterisk_cdr_csv

_FIXTURE = Path(__file__).parent / "fixtures" / "cdr" / "sample_master.csv"


class TestCDRParsing:
    def test_parses_all_records(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        assert len(records) == 13

    def test_fields_parsed_correctly(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        first = records[0]
        assert first.src == "2001"
        assert first.dst == "442071234567"
        assert first.disposition == "ANSWERED"
        assert first.billsec == 197
        assert first.answered is True

    def test_unanswered_call_has_none_answer_time(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        unanswered = next(r for r in records if r.disposition == "NO ANSWER")
        assert unanswered.answer is None
        assert unanswered.answered is False
        assert unanswered.billsec == 0

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(CDRParseError, match="not found"):
            parse_asterisk_cdr_csv(tmp_path / "nope.csv")

    def test_wrong_field_count_raises(self, tmp_path):
        bad = tmp_path / "bad.csv"
        bad.write_text("a,b,c,d,e,f\n")
        with pytest.raises(CDRParseError, match="expected 16-18 fields"):
            parse_asterisk_cdr_csv(bad)

    def test_empty_start_timestamp_raises(self, tmp_path):
        bad = tmp_path / "bad.csv"
        bad.write_text(
            '"","2001","442071234567","from-internal","clid","chan","dstchan",'
            '"Dial","data","","2026-01-01 10:00:05","2026-01-01 10:00:30",'
            '25,25,"ANSWERED","DOCUMENTATION"\n'
        )
        with pytest.raises(CDRParseError, match="'start' timestamp is empty"):
            parse_asterisk_cdr_csv(bad)

    def test_optional_uniqueid_and_userfield_default_empty(self, tmp_path):
        """16-field rows (no uniqueid/userfield) are valid per
        Asterisk's own documentation — both are explicitly optional."""
        minimal = tmp_path / "minimal.csv"
        minimal.write_text(
            '"","2001","442071234567","from-internal","clid","chan","dstchan",'
            '"Dial","data","2026-01-01 10:00:00","2026-01-01 10:00:05",'
            '"2026-01-01 10:00:30",30,25,"ANSWERED","DOCUMENTATION"\n'
        )
        records = parse_asterisk_cdr_csv(minimal)
        assert len(records) == 1
        assert records[0].uniqueid == ""
        assert records[0].userfield == ""

    def test_blank_lines_skipped_not_treated_as_malformed(self, tmp_path):
        f = tmp_path / "with_blanks.csv"
        f.write_text(
            '"","2001","442071234567","from-internal","clid","chan","dstchan",'
            '"Dial","data","2026-01-01 10:00:00","2026-01-01 10:00:05",'
            '"2026-01-01 10:00:30",30,25,"ANSWERED","DOCUMENTATION"\n\n\n'
        )
        records = parse_asterisk_cdr_csv(f)
        assert len(records) == 1


class TestTollFraudAnalysis:
    def test_analyzes_full_fixture_correctly(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(records, source_label="test.csv")
        assert result.records_analyzed == 13
        # 3 high-risk-destination findings (+252, +1268, +1809) + 1
        # off-hours + 1 burst = 5, confirmed by actually running the
        # analyzer against this fixture, not assumed from the rule
        # descriptions alone.
        assert len(result.findings) == 5

    def test_high_risk_destination_detected_with_correct_grouping(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(records, source_label="test.csv")
        somalia = next(f for f in result.findings if "+252" in f.title)
        assert somalia.severity.value == "CRITICAL"
        assert "4 answered call(s)" in somalia.description
        assert "2003" in somalia.description

    def test_off_hours_burst_detected(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(records, source_label="test.csv")
        off_hours = next(f for f in result.findings if "Off-hours" in f.title)
        assert "2003" in off_hours.title
        assert off_hours.severity.value == "HIGH"  # international destinations present

    def test_rapid_burst_detected(self):
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(records, source_label="test.csv")
        burst = next(f for f in result.findings if "burst" in f.title.lower())
        assert "2005" in burst.title
        assert burst.severity.value == "HIGH"

    def test_ordinary_business_hours_calls_produce_no_findings(self):
        """Regression-style test confirming no false positive: the
        extensions making entirely ordinary UK/Portugal business-hours
        calls (2001, 2002) must not appear in any finding at all."""
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(records, source_label="test.csv")
        all_text = " ".join(f.title + f.description for f in result.findings)
        assert "2001" not in all_text
        assert "2002" not in all_text

    def test_unanswered_call_excluded_from_high_risk_destination_check(self):
        """The unanswered call (ext 2006, NO ANSWER) is to an ordinary
        Portugal mobile number anyway, but this specifically confirms
        the 'unanswered calls generate no billable fraud revenue' logic
        by checking the source extension never appears in findings."""
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(records, source_label="test.csv")
        all_text = " ".join(f.title + f.description for f in result.findings)
        assert "2006" not in all_text

    def test_empty_records_produce_no_findings_no_crash(self):
        result = analyze_toll_fraud([], source_label="empty.csv")
        assert result.findings == []
        assert result.records_analyzed == 0

    def test_custom_business_hours_window_respected(self):
        """The 03:xx calls are off-hours under the default 7-21
        window, but should NOT be flagged as off-hours under a
        (contrived) 24-hour business window."""
        records = parse_asterisk_cdr_csv(_FIXTURE)
        result = analyze_toll_fraud(
            records, source_label="test.csv", business_start_hour=0, business_end_hour=24,
        )
        assert not any("Off-hours" in f.title for f in result.findings)
