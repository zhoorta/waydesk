//! Clipboard images: conversion between the RDP format CF_DIB and PNG, which is what Wayland applications exchange.
//! Both inputs are untrusted (the client's bitmap, the session's PNG), so every size is checked before anything is
//! allocated, and anything unusual is refused rather than guessed at.

use std::io::Cursor;

/// Most pixels an image may have (16 megapixels: 48 MB as RGB).
pub const MAX_PIXELS: u64 = 16 * 1024 * 1024;
/// Longest side of an image.
const MAX_SIDE: u32 = 16384;

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn size_ok(w: u32, h: u32) -> bool {
    w > 0 && h > 0 && w <= MAX_SIDE && h <= MAX_SIDE && u64::from(w) * u64::from(h) <= MAX_PIXELS
}

/// A CF_DIB (BITMAPINFOHEADER and pixels, no file header) of 24 or 32 bits per pixel, as a PNG. Transparency is not
/// carried: CF_DIB has none that applications agree on, so the picture is opaque.
pub fn dib_to_png(dib: &[u8]) -> Option<Vec<u8>> {
    let header = le32(dib, 0)? as usize;
    if !matches!(header, 40 | 108 | 124) {
        return None;
    }
    let width = i32::from_le_bytes(dib.get(4..8)?.try_into().ok()?);
    let height = i32::from_le_bytes(dib.get(8..12)?.try_into().ok()?);
    let bpp = le16(dib, 14)?;
    let compression = le32(dib, 16)?;
    let colors_used = le32(dib, 32)? as usize;
    if width <= 0 || height == 0 || height == i32::MIN {
        return None;
    }
    let (w, h) = (width as u32, height.unsigned_abs());
    if !size_ok(w, h) || !matches!(bpp, 24 | 32) {
        return None;
    }
    // BI_RGB, or BI_BITFIELDS with the ordinary blue-green-red masks (anything else is not understood).
    let mut offset = header;
    match compression {
        0 => {}
        3 => {
            if bpp != 32 {
                return None;
            }
            if header == 40 {
                if (le32(dib, 40)?, le32(dib, 44)?, le32(dib, 48)?) != (0x00FF_0000, 0x0000_FF00, 0x0000_00FF) {
                    return None;
                }
                offset += 12;
            } else if (le32(dib, 40)?, le32(dib, 44)?, le32(dib, 48)?) != (0x00FF_0000, 0x0000_FF00, 0x0000_00FF) {
                return None;
            }
        }
        _ => return None,
    }
    offset = offset.checked_add(colors_used.min(256) * 4)?;
    let bytes_pp = usize::from(bpp / 8);
    let stride = (w as usize * bytes_pp).div_ceil(4) * 4;
    let pixels = dib.get(offset..)?;
    if pixels.len() < stride.checked_mul(h as usize)? {
        return None;
    }
    let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
    for y in 0..h as usize {
        // A positive height means the bottom row comes first.
        let row = if height > 0 { h as usize - 1 - y } else { y };
        let line = &pixels[row * stride..row * stride + w as usize * bytes_pp];
        for px in line.chunks_exact(bytes_pp) {
            rgb.extend_from_slice(&[px[2], px[1], px[0]]);
        }
    }
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, w, h);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.set_compression(png::Compression::Fast);
    let mut writer = enc.write_header().ok()?;
    writer.write_image_data(&rgb).ok()?;
    writer.finish().ok()?;
    Some(out)
}

/// Whether `data` is a PNG whose declared size is within the limits (the header only: applications decode it themselves).
pub fn png_within_limits(data: &[u8]) -> bool {
    let mut dec = png::Decoder::new(Cursor::new(data));
    dec.set_limits(png::Limits { bytes: 3 * MAX_PIXELS as usize });
    dec.read_info().is_ok_and(|r| size_ok(r.info().width, r.info().height))
}

/// A PNG as a CF_DIB: 24 bits per pixel, bottom row first; transparent parts are shown on white.
pub fn png_to_dib(data: &[u8]) -> Option<Vec<u8>> {
    let mut dec = png::Decoder::new(Cursor::new(data));
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    dec.set_limits(png::Limits { bytes: 3 * MAX_PIXELS as usize });
    let mut reader = dec.read_info().ok()?;
    let info = reader.info();
    let (w, h) = (info.width, info.height);
    if !size_ok(w, h) {
        return None;
    }
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut buf).ok()?;
    if frame.bit_depth != png::BitDepth::Eight {
        return None;
    }
    let channels = match frame.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return None,
    };
    let (w, h) = (w as usize, h as usize);
    if frame.line_size < w * channels || buf.len() < frame.line_size * h {
        return None;
    }
    let stride = (w * 3).div_ceil(4) * 4;
    let mut dib = Vec::with_capacity(40 + stride * h);
    dib.extend_from_slice(&40u32.to_le_bytes());
    dib.extend_from_slice(&(w as i32).to_le_bytes());
    dib.extend_from_slice(&(h as i32).to_le_bytes());
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&24u16.to_le_bytes());
    dib.extend_from_slice(&0u32.to_le_bytes());
    dib.extend_from_slice(&((stride * h) as u32).to_le_bytes());
    dib.extend_from_slice(&[0u8; 16]);
    let over_white = |c: u8, a: u8| ((u16::from(c) * u16::from(a) + 255 * (255 - u16::from(a)) + 127) / 255) as u8;
    for y in (0..h).rev() {
        let line = &buf[y * frame.line_size..y * frame.line_size + w * channels];
        let start = dib.len();
        for px in line.chunks_exact(channels) {
            let (r, g, b) = match channels {
                1 => (px[0], px[0], px[0]),
                2 => (over_white(px[0], px[1]), over_white(px[0], px[1]), over_white(px[0], px[1])),
                3 => (px[0], px[1], px[2]),
                _ => (over_white(px[0], px[3]), over_white(px[1], px[3]), over_white(px[2], px[3])),
            };
            dib.extend_from_slice(&[b, g, r]);
        }
        dib.resize(start + stride, 0);
    }
    Some(dib)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dib_header(w: i32, h: i32, bpp: u16, compression: u32) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&40u32.to_le_bytes());
        d.extend_from_slice(&w.to_le_bytes());
        d.extend_from_slice(&h.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&bpp.to_le_bytes());
        d.extend_from_slice(&compression.to_le_bytes());
        d.extend_from_slice(&[0u8; 20]);
        d
    }

    #[test]
    fn a_dib_survives_the_round_trip_through_png() {
        // 2x2, 24 bits, bottom row first: row stride is 8 bytes (6 + 2 padding).
        let mut dib = dib_header(2, 2, 24, 0);
        dib.extend_from_slice(&[0, 0, 255, 0, 255, 0, 0, 0]); // bottom: red, green (BGR order)
        dib.extend_from_slice(&[255, 0, 0, 255, 255, 255, 0, 0]); // top: blue, white
        let png = dib_to_png(&dib).expect("png");
        assert_eq!(&png[..4], b"\x89PNG");
        let back = png_to_dib(&png).expect("dib");
        assert_eq!(back[40..], dib[40..]);
    }

    #[test]
    fn a_top_down_32_bit_dib_is_read() {
        let mut dib = dib_header(1, -2, 32, 0);
        dib.extend_from_slice(&[10, 20, 30, 0, 40, 50, 60, 0]);
        let png = dib_to_png(&dib).expect("png");
        let back = png_to_dib(&png).expect("dib");
        // Bottom row first in the 24 bit result: second input row, then the first.
        assert_eq!(&back[40..43], &[40, 50, 60]);
        assert_eq!(&back[44..47], &[10, 20, 30]);
    }

    #[test]
    fn transparent_pixels_become_white() {
        let mut out = Vec::new();
        let mut enc = png::Encoder::new(&mut out, 1, 1);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&[0, 0, 0, 0]).unwrap();
        w.finish().unwrap();
        let dib = png_to_dib(&out).unwrap();
        assert_eq!(&dib[40..43], &[255, 255, 255]);
    }

    #[test]
    fn hostile_dibs_are_refused() {
        assert!(dib_to_png(&[]).is_none());
        assert!(dib_to_png(&[0; 40]).is_none(), "zero size");
        // Declares 16000x16000 but carries no pixels.
        assert!(dib_to_png(&dib_header(16000, 16000, 24, 0)).is_none(), "too many pixels / too little data");
        assert!(dib_to_png(&dib_header(100_000, 1, 24, 0)).is_none(), "side too long");
        assert!(dib_to_png(&dib_header(i32::MAX, i32::MIN, 24, 0)).is_none());
        assert!(dib_to_png(&dib_header(1, 1, 24, 1)).is_none(), "RLE");
        assert!(dib_to_png(&dib_header(1, 1, 8, 0)).is_none(), "palette");
    }

    #[test]
    fn png_limits_are_checked_on_the_header() {
        let mut out = Vec::new();
        let mut enc = png::Encoder::new(&mut out, 4, 4);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&[0u8; 16]).unwrap();
        w.finish().unwrap();
        assert!(png_within_limits(&out));
        assert!(!png_within_limits(b"nope"));
        let mut big = Vec::new();
        let mut enc = png::Encoder::new(&mut big, 20000, 1);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&vec![0u8; 20000]).unwrap();
        w.finish().unwrap();
        assert!(!png_within_limits(&big));
    }

    #[test]
    fn hostile_pngs_are_refused() {
        assert!(png_to_dib(b"not a png").is_none());
        assert!(png_to_dib(&[]).is_none());
        // A valid PNG of 20000x1 (side too long) must be refused before it is decoded.
        let mut out = Vec::new();
        let mut enc = png::Encoder::new(&mut out, 20000, 1);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&vec![0u8; 20000]).unwrap();
        w.finish().unwrap();
        assert!(png_to_dib(&out).is_none());
    }
}
