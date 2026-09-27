// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/image-decoders/image_decoder_fuzzer_utils.h"

#include <algorithm>
#include <vector>

#include "base/containers/span.h"
#include "third_party/blink/renderer/platform/graphics/color_behavior.h"
#include "third_party/blink/renderer/platform/image-decoders/avif/avif_image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/bmp/bmp_image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/bmp/bmp_rust_image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/png/png_image_decoder.h"

#if BUILDFLAG(ENABLE_JXL_DECODER)
#include "third_party/blink/renderer/platform/image-decoders/jxl/jxl_image_decoder.h"
#endif

namespace blink {

ColorBehavior GetColorBehavior(FuzzedDataProvider& fdp) {
  switch (fdp.ConsumeIntegralInRange(1, 3)) {
    case 1:
      return ColorBehavior::kIgnore;
    case 2:
      return ColorBehavior::kTag;
    case 3:
      return ColorBehavior::kTransformToSRGB;
    default:
      return ColorBehavior::kIgnore;
  }
}

ImageDecoder::AnimationOption GetAnimationOption(FuzzedDataProvider& fdp) {
  switch (fdp.ConsumeIntegralInRange(1, 3)) {
    case 1:
      return ImageDecoder::AnimationOption::kUnspecified;
    case 2:
      return ImageDecoder::AnimationOption::kPreferAnimation;
    case 3:
      return ImageDecoder::AnimationOption::kPreferStillImage;
    default:
      return ImageDecoder::AnimationOption::kUnspecified;
  }
}

ImageDecoder::HighBitDepthDecodingOption GetHbdOption(FuzzedDataProvider& fdp) {
  return fdp.ConsumeBool() ? ImageDecoder::kDefaultBitDepth
                           : ImageDecoder::kHighBitDepthToHalfFloat;
}

cc::AuxImage GetAuxImageType(FuzzedDataProvider& fdp) {
  return fdp.ConsumeBool() ? cc::AuxImage::kDefault : cc::AuxImage::kGainmap;
}

ImageDecoder::AlphaOption GetAlphaOption(FuzzedDataProvider& fdp) {
  return fdp.ConsumeBool() ? ImageDecoder::kAlphaPremultiplied
                           : ImageDecoder::kAlphaNotPremultiplied;
}

std::unique_ptr<ImageDecoder> CreateImageDecoder(DecoderType decoder_type,
                                                 FuzzedDataProvider& fdp) {
  switch (decoder_type) {
    case DecoderType::kBmpDecoder:
      return std::make_unique<BMPImageDecoder>(
          GetAlphaOption(fdp), GetColorBehavior(fdp),
          /*max_decoded_bytes=*/fdp.ConsumeIntegral<uint32_t>());
    case DecoderType::kBmpRustDecoder:
      return std::make_unique<BmpRustImageDecoder>(
          GetAlphaOption(fdp), GetColorBehavior(fdp),
          /*max_decoded_bytes=*/fdp.ConsumeIntegral<uint32_t>());
    case DecoderType::kJpegDecoder: {
      return std::make_unique<JPEGImageDecoder>(
          GetAlphaOption(fdp), GetColorBehavior(fdp), GetAuxImageType(fdp),
          /*max_decoded_bytes=*/fdp.ConsumeIntegral<uint32_t>());
    }
    case DecoderType::kPngDecoder: {
      return std::make_unique<PngImageDecoder>(
          GetAlphaOption(fdp), GetColorBehavior(fdp),
          /*max_decoded_bytes=*/fdp.ConsumeIntegral<uint32_t>(),
          /*offset=*/fdp.ConsumeIntegral<uint32_t>(),
          /*bit_depth_option=*/GetHbdOption(fdp));
    }
    case DecoderType::kAvifDecoder: {
      return std::make_unique<AVIFImageDecoder>(
          GetAlphaOption(fdp), GetHbdOption(fdp), GetColorBehavior(fdp),
          GetAuxImageType(fdp),
          /*max_decoded_bytes=*/fdp.ConsumeIntegral<uint32_t>(),
          GetAnimationOption(fdp));
    }
#if BUILDFLAG(ENABLE_JXL_DECODER)
    case DecoderType::kJxlDecoder: {
      return std::make_unique<JXLImageDecoder>(
          GetAlphaOption(fdp), GetHbdOption(fdp), GetColorBehavior(fdp),
          GetAuxImageType(fdp),
          /*max_decoded_bytes=*/fdp.ConsumeIntegral<uint32_t>(),
          GetAnimationOption(fdp));
    }
#endif
  }
}

void FuzzDecoder(DecoderType decoder_type, FuzzedDataProvider& fdp) {
  auto decoder = CreateImageDecoder(decoder_type, fdp);
  auto remaining_data = fdp.ConsumeRemainingBytes<char>();
  auto buffer = SharedBuffer::Create(remaining_data);
  const bool kAllDataReceived = true;
  decoder->SetData(buffer.get(), kAllDataReceived);
  for (wtf_size_t frame = 0; frame < decoder->FrameCount(); ++frame) {
    decoder->DecodeFrameBufferAtIndex(frame);
    if (decoder->Failed()) {
      return;
    }
  }
}

void FuzzIncrementalDecoder(DecoderType decoder_type, FuzzedDataProvider& fdp) {
  std::unique_ptr<ImageDecoder> decoder = CreateImageDecoder(decoder_type, fdp);
  const size_t op_count = fdp.ConsumeIntegralInRange<size_t>(1, 32);
  std::vector<std::pair<uint8_t, uint8_t>> ops;
  ops.reserve(op_count);
  for (size_t i = 0; i < op_count; ++i) {
    const uint8_t op = fdp.ConsumeIntegral<uint8_t>();
    const uint8_t arg = fdp.ConsumeIntegral<uint8_t>();
    ops.emplace_back(op, arg);
  }
  auto image = fdp.ConsumeRemainingBytes<char>();

  size_t delivered = 0;
  for (const auto& [op, arg] : ops) {
    if (decoder->Failed()) {
      break;
    }
    if ((op % 5) != 0 && delivered == 0) {
      continue;
    }

    switch (op % 5) {
      case 0:
        delivered = std::min<size_t>(image.size(),
                                     delivered + std::max<size_t>(1, arg));
        decoder->SetData(
            SharedBuffer::Create(base::span(image).first(delivered)),
            delivered == image.size() && (arg & 1));
        break;
      case 1:
        decoder->FrameCount();
        decoder->RepetitionCount();
        break;
      case 2: {
        wtf_size_t n = decoder->FrameCount();
        if (n) {
          decoder->DecodeFrameBufferAtIndex(arg % n);
        }
        break;
      }
      case 3: {
        wtf_size_t n = decoder->FrameCount();
        if (arg & 1) {
          decoder->ClearCacheExceptFrame(kNotFound);
        } else {
          decoder->ClearCacheExceptFrame(n ? arg % n : 0);
        }
        break;
      }
      case 4: {
        decoder->IsSizeAvailable();
        decoder->Size();
        decoder->HasEmbeddedColorProfile();
        wtf_size_t n = decoder->FrameCount();
        if (n) {
          wtf_size_t frame = arg % n;
          decoder->FrameIsReceivedAtIndex(frame);
          decoder->FrameDurationAtIndex(frame);
          decoder->FrameHasAlphaAtIndex(frame);
        }
        break;
      }
    }
  }

  if (decoder->Failed()) {
    return;
  }

  decoder->SetData(SharedBuffer::Create(base::span(image)),
                   /*all_data_received=*/true);
  for (wtf_size_t frame = 0; frame < decoder->FrameCount(); ++frame) {
    decoder->DecodeFrameBufferAtIndex(frame);
    if (decoder->Failed()) {
      return;
    }
  }
}

}  // namespace blink
