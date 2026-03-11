#include "ForensicImageExtractor/forensics/VolumeEnumerator.h"

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::forensics {

std::vector<domain::PartitionInfo> VolumeEnumerator::enumerate(const core::TskImageHandleAdapter &image,
                                                               QString &error) const {
  std::vector<domain::PartitionInfo> out;
  if (!image.isOpen()) {
    error = "Cannot enumerate partitions: TSK image not open";
    return out;
  }

#if defined(FIE_HAS_TSK)
  TSK_VS_INFO *vs = tsk_vs_open(image.img(), 0, TSK_VS_TYPE_DETECT);
  if (!vs) {
    domain::PartitionInfo whole;
    whole.index = 0;
    whole.identifier = "p0";
    whole.startOffset = 0;
    whole.length = image.img()->size;
    whole.description = "No partition table detected";
    whole.fileSystemType = "Unknown";
    out.push_back(whole);
    return out;
  }

  for (TSK_PNUM_T i = 0; i < vs->part_count; ++i) {
    const TSK_VS_PART_INFO *part = tsk_vs_part_get(vs, i);
    if (!part) {
      continue;
    }
    if (part->flags & TSK_VS_PART_FLAG_META) {
      continue;
    }

    domain::PartitionInfo p;
    p.index = static_cast<int>(i);
    p.identifier = QString("p%1").arg(i);
    p.startOffset = static_cast<quint64>(part->start) * vs->block_size;
    p.length = static_cast<quint64>(part->len) * vs->block_size;
    p.description = QString::fromUtf8(part->desc ? part->desc : "");
    p.fileSystemType = "Detect";
    out.push_back(std::move(p));
  }

  tsk_vs_close(vs);
  if (out.empty()) {
    error = "No allocatable partitions found";
  }
#else
  error = "TSK support is unavailable at build time";
#endif

  return out;
}

} // namespace fie::forensics
