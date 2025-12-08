#include "fec_decoder.h"
#include "../common/packet_format.h"
#include "zfec.h"  // 假设使用修改后的zfec库

class FecDecoder {
private:
    ZFE_FEC fec;
    std::map<uint32_t, std::vector<DataBlock>> frame_blocks;  // 按帧索引存储块

public:
    FecDecoder() {
        fec.init_fec();  // 初始化FEC
    }

    // 输入FEC编码块
    bool add_block(uint32_t frame_idx, uint8_t part_idx, 
                  bool is_last, const uint8_t* data, size_t size,
                  uint8_t fec_k, uint8_t fec_n,
                  std::vector<uint8_t>& out_frame) {

        // 存储块数据
        DataBlock block;
        block.part_idx = part_idx;
        block.data.assign(data, data + size);
        frame_blocks[frame_idx].push_back(block);

        // 检查是否收集到足够的块
        auto& blocks = frame_blocks[frame_idx];
        if (blocks.size() < fec_k) return false;

        // 创建FEC解码器
        auto* code = fec.fec_new(fec_k, fec_n);
        if (!code) return false;

        // 准备解码缓冲区
        std::vector<const uint8_t*> in_blocks(fec_k);
        std::vector<unsigned> indices(fec_k);
        for (int i = 0; i < fec_k && i < blocks.size(); i++) {
            in_blocks[i] = blocks[i].data.data();
            indices[i] = blocks[i].part_idx;
        }

        // 计算每个块的大小
        size_t block_size = blocks[0].data.size();
        std::vector<uint8_t> decoded_data(fec_k * block_size);
        std::vector<uint8_t*> out_blocks(fec_k);
        for (int i = 0; i < fec_k; i++) {
            out_blocks[i] = decoded_data.data() + i * block_size;
        }

        // 执行FEC解码
        fec.fec_decode(code, in_blocks.data(), out_blocks.data(), indices.data(), block_size);
        fec.fec_free(&code);

        // 拼接解码后的数据
        out_frame.clear();
        for (int i = 0; i < fec_k; i++) {
            out_frame.insert(out_frame.end(), 
                           out_blocks[i], out_blocks[i] + block_size);
        }

        // 如果是最后一个块，清理缓存
        if (is_last) {
            frame_blocks.erase(frame_idx);
        }

        return true;
    }
};