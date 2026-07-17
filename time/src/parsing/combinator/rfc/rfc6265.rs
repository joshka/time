//! RFC 6265 `cookie-date` parsing.
//!
//! This implements the user-agent date parser from RFC 6265 section 5.1.1:
//! <https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.1>.
//! That algorithm tokenizes by delimiter octets, scans tokens in order, records
//! the first matching time, day, month, and year productions, then constructs a
//! UTC date-time. This does not parse a complete `Set-Cookie` header; section
//! 5.2.1 passes only the `Expires` attribute value to this algorithm.
//! See <https://datatracker.ietf.org/doc/html/rfc6265#section-5.2.1>.
//! This follows verified RFC Errata 4148 for the optional trailing data in the
//! day, year, and time productions: <https://www.rfc-editor.org/errata/eid4148>.

use num_conv::prelude::*;

use crate::error::ParseFromDescription::InvalidComponent;
use crate::error::TryFromParsed;
use crate::format_description::modifier;
use crate::parsing::combinator::{ascii_char, one_or_two_digits};
use crate::parsing::{ParsedItem, component};
use crate::{Date, Month, OffsetDateTime, Time, UtcOffset, error};

pub(crate) fn invalid_component(name: &'static str) -> error::Parse {
    error::Parse::ParseFromDescription(InvalidComponent(name))
}

#[derive(Default)]
struct Parsed {
    time: Option<(u8, u8, u8)>,
    day: Option<u8>,
    month: Option<Month>,
    year: Option<i32>,
}

fn is_delimiter(byte: u8) -> bool {
    // RFC 6265 section 5.1.1 defines delimiter as HTAB, space through slash,
    // semicolon through at-sign, left bracket through grave accent, and left
    // brace through tilde. Bytes outside those ranges are part of date-token.
    byte == b'\t'
        || (0x20..=0x2F).contains(&byte)
        || (0x3B..=0x40).contains(&byte)
        || (0x5B..=0x60).contains(&byte)
        || (0x7B..=0x7E).contains(&byte)
}

fn ends_at_non_digit(input: &[u8], index: usize) -> bool {
    // Verified RFC Errata 4148 corrects the day, year, and time productions
    // from requiring trailing non-digit data to allowing either end-of-token
    // or `non-digit *OCTET`.
    match input.get(index) {
        Some(byte) => !byte.is_ascii_digit(),
        None => true,
    }
}

fn parse_time(input: &[u8]) -> Option<(u8, u8, u8)> {
    // time = hms-time [ non-digit *OCTET ], after RFC Errata 4148. Each hms
    // component is 1*2 DIGIT.
    // Range validation is deliberately later, matching the RFC's sequence of
    // first finding components and then rejecting invalid parsed values.
    let ParsedItem(input, hour) = one_or_two_digits(input)?;
    let input = ascii_char::<b':'>(input)?.into_inner();
    let ParsedItem(input, minute) = one_or_two_digits(input)?;
    let input = ascii_char::<b':'>(input)?.into_inner();
    let ParsedItem(input, second) = one_or_two_digits(input)?;
    ends_at_non_digit(input, 0).then_some((hour, minute, second))
}

/// Parse the RFC 6265 day-of-month production without applying the day range check.
///
/// The RFC records the first syntactic day token before it rejects `0` in the
/// later range checks. Using `component::parse_day` here would reject `0` too
/// early and allow a later numeric token to become the day.
fn parse_day(input: &[u8]) -> Option<u8> {
    // day-of-month = 1*2 DIGIT [ non-digit *OCTET ], after RFC Errata 4148.
    let ParsedItem(input, day) = one_or_two_digits(input)?;
    ends_at_non_digit(input, 0).then_some(day)
}

/// Parse the RFC 6265 month production using the shared short-month parser.
///
/// RFC ABNF string literals are case-insensitive, and the production permits
/// arbitrary trailing octets after the three-letter month prefix. The shared
/// parser returns those trailing bytes as the remainder; RFC 6265 requires that
/// remainder to be ignored.
fn parse_month(input: &[u8]) -> Option<Month> {
    let modifiers = modifier::MonthShort {
        case_sensitive: false,
    };
    component::parse_month_short(input, modifiers).map(|item| item.1)
}

fn parse_year(input: &[u8]) -> Option<i32> {
    // year = 2*4 DIGIT [ non-digit *OCTET ], after RFC Errata 4148. The
    // adjustment below follows the RFC's numeric year-value rules: 70..=99 map
    // to 1970..=1999, and 0..=69 map to 2000..=2069.
    let mut value = 0_u16;
    let mut index = 0;

    while index < 4 {
        let Some(byte) = input.get(index).copied() else {
            break;
        };
        if !byte.is_ascii_digit() {
            break;
        }

        value = value * 10 + (byte - b'0').widen::<u16>();
        index += 1;
    }

    if !(2..=4).contains(&index) || !ends_at_non_digit(input, index) {
        return None;
    }

    // The RFC normalizes the numeric year-value, not the original token width.
    // Therefore "0069" parses as year-value 69 and maps to 2069.
    Some(match value {
        0..=69 => value.cast_signed().widen::<i32>() + 2000,
        70..=99 => value.cast_signed().widen::<i32>() + 1900,
        _ => value.cast_signed().widen::<i32>(),
    })
}

pub(crate) fn parse(input: &[u8]) -> Result<OffsetDateTime, error::Parse> {
    let mut parsed = Parsed::default();

    for token in input
        .split(|byte| is_delimiter(*byte))
        .filter(|token| !token.is_empty())
    {
        // Section 5.1.1 checks productions in this order: time, day, month,
        // year. Once a token matches a production, the RFC says to skip the
        // remaining sub-steps and continue to the next token. That syntactic
        // match sets the found flag even if a later range check rejects the
        // value, so the parser must not recover by using a later token for the
        // same component. Unrelated tokens such as weekday names and time zone
        // labels are ignored rather than rejected.
        if parsed.time.is_none()
            && let Some(time) = parse_time(token)
        {
            parsed.time = Some(time);
            continue;
        }

        if parsed.day.is_none()
            && let Some(day) = parse_day(token)
        {
            parsed.day = Some(day);
            continue;
        }

        if parsed.month.is_none()
            && let Some(month) = parse_month(token)
        {
            parsed.month = Some(month);
            continue;
        }

        if parsed.year.is_none()
            && let Some(year) = parse_year(token)
        {
            parsed.year = Some(year);
        }
    }

    let year = parsed.year.ok_or_else(|| invalid_component("year"))?;
    let month = parsed.month.ok_or_else(|| invalid_component("month"))?;
    let day = parsed.day.ok_or_else(|| invalid_component("day"))?;
    let (hour, minute, second) = parsed.time.ok_or_else(|| invalid_component("hour"))?;

    // Section 5.1.1 rejects missing fields, year < 1601, out-of-range
    // day/hour/minute/second values, leap seconds, and nonexistent calendar
    // dates. Calendar validity is delegated to Date::from_calendar_date below.
    if year < 1601 {
        return Err(invalid_component("year"));
    }
    if !(1..=31).contains(&day) {
        return Err(invalid_component("day"));
    }
    if hour > 23 {
        return Err(invalid_component("hour"));
    }
    if minute > 59 {
        return Err(invalid_component("minute"));
    }
    if second > 59 {
        return Err(invalid_component("second"));
    }

    let date = Date::from_calendar_date(year, month, day)
        .map_err(|err| error::Parse::TryFromParsed(TryFromParsed::ComponentRange(err)))?;
    let time = Time::from_hms(hour, minute, second)
        .map_err(|err| error::Parse::TryFromParsed(TryFromParsed::ComponentRange(err)))?;

    // The final step says to let parsed-cookie-date be the resulting date in UTC.
    Ok(OffsetDateTime::new_in_offset(date, time, UtcOffset::UTC))
}
