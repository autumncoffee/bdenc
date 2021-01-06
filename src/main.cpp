#include <ac-common/file.hpp>
#include <ac-common/str.hpp>
#include <ac-common/utils/string.hpp>
#include <ac-common/utils/htonll.hpp>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <iostream>
#include <string>
#include <utility>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <random>
#include <time.h>

#ifdef RELEASE_FILESYSTEM
#include <filesystem>

namespace stdfs = std::filesystem;

#else
#include <experimental/filesystem>

namespace stdfs = std::experimental::filesystem;
#endif

enum TMode {
    MODE_ENCRYPT,
    MODE_DECRYPT,

    MODE_DEFAULT,
};

template<typename... TArgs>
bool CreateFile(const std::string& path, TArgs&&... args) {
    NAC::TFile file(path, NAC::TFile::ACCESS_CREATE);

    if (!file) {
        std::cerr << "Can't create " << path << std::endl;
        return false;
    }

    file.Append(std::forward<TArgs>(args)...);
    file.FSync();

    if (!file) {
        std::cerr << "Can't create " << path << std::endl;
        return false;
    }

    return true;
}

bool CreateRandomFile(const size_t size, const std::string& path) {
    static std::random_device rd;
    static std::mt19937 g(rd());
    static std::uniform_int_distribution<unsigned char> dis(0, 255);

    NAC::TBlob content;

    for (size_t i = 0; i < size; ++i) {
        char chr(dis(g));

        content.Append(1, &chr);
    }

    return CreateFile(path, content.Size(), content.Data());
}

template<typename... TArgs>
int EVPInitWrapper(const TMode mode, TArgs&&... args) {
    if (mode == MODE_ENCRYPT) {
        return EVP_EncryptInit_ex(std::forward<TArgs>(args)...);

    } else {
        return EVP_DecryptInit_ex(std::forward<TArgs>(args)...);
    }
}

template<typename... TArgs>
int EVPUpdateWrapper(const TMode mode, TArgs&&... args) {
    if (mode == MODE_ENCRYPT) {
        return EVP_EncryptUpdate(std::forward<TArgs>(args)...);

    } else {
        return EVP_DecryptUpdate(std::forward<TArgs>(args)...);
    }
}

template<typename... TArgs>
int EVPFinalWrapper(const TMode mode, TArgs&&... args) {
    if (mode == MODE_ENCRYPT) {
        return EVP_EncryptFinal_ex(std::forward<TArgs>(args)...);

    } else {
        return EVP_DecryptFinal_ex(std::forward<TArgs>(args)...);
    }
}

int main(int argc, char** argv) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0] << " -m enc|dec -w /path/to/workdir [-n] [-s 4096] /path/to/file" << std::endl;
        return 1;
    }

    std::string devPath;
    std::string workdirPath;
    bool dryRun(false);
    TMode mode(MODE_DEFAULT);
    size_t chunkSize(4096);

    for (size_t i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-m") == 0) {
            ++i;

            if (strcmp(argv[i], "enc") == 0) {
                mode = MODE_ENCRYPT;

            } else if (strcmp(argv[i], "dec") == 0) {
                mode = MODE_DECRYPT;

            } else {
                std::cerr << "Invalid mode: " << argv[i] << std::endl;
                return 1;
            }

        } else if (strcmp(argv[i], "-w") == 0) {
            ++i;
            workdirPath = argv[i];

        } else if (strcmp(argv[i], "-n") == 0) {
            dryRun = true;

        } else if (strcmp(argv[i], "-s") == 0) {
            ++i;
            NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], chunkSize);

        } else if (devPath.empty()) {
            devPath = argv[i];

        } else {
            std::cerr << "Invalid argument: " << argv[i] << std::endl;
            return 1;
        }
    }

    if (devPath.empty()) {
        std::cerr << "No file specified" << std::endl;
        return 1;
    }

    if (workdirPath.empty()) {
        std::cerr << "No workdir specified" << std::endl;
        return 1;
    }

    if (mode == MODE_DEFAULT) {
        std::cerr << "No mode specified" << std::endl;
        return 1;
    }

    const std::string modeName((mode == MODE_ENCRYPT) ? "enc" : "dec");
    const std::string inverseModeName((mode == MODE_ENCRYPT) ? "dec" : "enc");

    static const size_t blockSize(16);
    static const size_t keySize(32);

    if ((chunkSize % blockSize) != 0) {
        std::cerr << "Chunk size (-s) must be multiple of " << blockSize << std::endl;
        return 1;
    }

    NAC::TFile dev(devPath, NAC::TFile::ACCESS_RDWR_DIRECT);

    if (!dev) {
        std::cerr << "Can't open file" << std::endl;
        return 1;
    }

    if ((dev.Size() % chunkSize) != 0) {
        std::cerr << "File size (" << dev.Size() << ") must be multiple of chunk size (-s " << chunkSize << ")" << std::endl;
        return 1;
    }

    const stdfs::path wd(workdirPath);
    const auto ivPath = wd / ".iv";
    const auto keyPath = wd / ".key";

    if (
        !stdfs::exists(ivPath)
        || !stdfs::exists(keyPath)
    ) {
        if (mode == MODE_DECRYPT) {
            std::cerr << "Key and/or iv absent" << std::endl;
            return 1;
        }

        if (!CreateRandomFile(blockSize, ivPath.string())) {
            return 1;
        }

        if (!CreateRandomFile(keySize, keyPath.string())) {
            return 1;
        }
    }

    NAC::TFile iv(ivPath.string());
    NAC::TFile key(keyPath.string());

    if (!iv || !key || (iv.Size() != blockSize) || (key.Size() != keySize)) {
        std::cerr << "Can't load key and/or iv" << std::endl;
        return 1;
    }

    EVP_CIPHER_CTX* ctx(EVP_CIPHER_CTX_new());

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVPInitWrapper(mode, ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.Data(), (const unsigned char*)iv.Data())) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    {
        const auto detectedBlockSize = EVP_CIPHER_CTX_block_size(ctx);

        if (detectedBlockSize != blockSize) {
            std::cerr << "Detected block size (" << detectedBlockSize << ") is not equal to expected block size (" << blockSize << ")" << std::endl;
            return 1;
        }
    }

    uint64_t offset(0);
    const auto offsetPath = wd / (modeName + "_offset");

    if (!stdfs::exists(offsetPath)) {
        uint64_t tmp(NAC::hton(offset));

        if (!CreateFile(offsetPath.string(), sizeof(tmp), (const char*)&tmp)) {
            return 1;
        }
    }

    NAC::TFile offsetFile(offsetPath.string(), NAC::TFile::ACCESS_RDWR);

    if (!offsetFile || (offsetFile.Size() != sizeof(offset))) {
        std::cerr << "Can't load offset file" << std::endl;
        return 1;
    }

    memcpy(&offset, offsetFile.Data(), offsetFile.Size());
    offset = NAC::ntoh(offset);

    if (offset >= dev.Size()) {
        std::cerr << "Already done" << std::endl;
        return 0;
    }

    const auto sparsePath = wd / (((mode == MODE_ENCRYPT) ? modeName : inverseModeName) + "_sparse");

    if (!stdfs::exists(sparsePath)) {
        if (!CreateFile(sparsePath.string(), 0, nullptr)) {
            return 1;
        }
    }

    NAC::TFile sparseFile(sparsePath.string(), ((mode == MODE_ENCRYPT) ? NAC::TFile::ACCESS_WRONLY : NAC::TFile::ACCESS_RDONLY));
    size_t sparseOffset(0);

    if (!sparseFile && ((mode == MODE_ENCRYPT) || (stdfs::exists(sparsePath) && !stdfs::is_empty(sparsePath)))) {
        std::cerr << "Can't load sparse file" << std::endl;
        return 1;
    }

    if (mode == MODE_ENCRYPT) {
        sparseFile.SeekToEnd();
    }

    NAC::TBlob zeros;
    zeros.Reserve(chunkSize);

    memset(zeros.Data(), 0, chunkSize);

    auto chunks = dev.Chunks(chunkSize);
    chunks.Seek(offset);

    NAC::TBlob block;
    block.Reserve(chunkSize);

    const size_t toProcess(dev.Size() - offset);
    size_t processed(0);
    size_t prevProcessed(processed);
    const time_t t0(time(nullptr));
    time_t prevTime(t0);

    while (auto chunk = chunks.Next()) {
        const auto tmpPath = wd / (modeName + "_chunk-" + std::to_string(offset));
        bool allZeroes(false);

        if (stdfs::exists(tmpPath)) {
            NAC::TFile tmp(tmpPath.string());

            if (!tmp || (tmp.Size() != chunkSize)) {
                std::cerr << "Can't load " << tmpPath.string() << std::endl;
                return 1;
            }

            if (!dryRun) {
                dev.Write(offset, tmp.Size(), tmp.Data());
                dev.FSync();

                if (!dev) {
                    std::cerr << "Failed at " << std::to_string(offset) << ": can't write to file" << std::endl;
                    return 1;
                }
            }

        } else {
            if (mode == MODE_ENCRYPT) {
                allZeroes = (0 == memcmp(chunk.Data(), zeros.Data(), chunk.Size()));

            } else if (sparseFile) {
                while (sparseOffset < sparseFile.Size()) {
                    uint64_t tmp;

                    memcpy(&tmp, sparseFile.Data() + sparseOffset, sizeof(tmp));
                    tmp = NAC::ntoh(tmp);

                    if (tmp < offset) {
                        sparseOffset += sizeof(tmp);

                    } else {
                        allZeroes = (tmp == offset);
                        break;
                    }
                }
            }

            if (allZeroes) {
                if (mode == MODE_ENCRYPT) {
                    uint64_t tmp(NAC::hton(offset));

                    sparseFile.Append(sizeof(tmp), (const char*)&tmp);
                    sparseFile.FSync();

                    if (!sparseFile) {
                        std::cerr << "Failed at " << std::to_string(offset) << ": can't save sparse file" << std::endl;
                        return 1;
                    }
                }

            } else {
                int len(0);

                if (1 != EVPUpdateWrapper(mode, ctx, (unsigned char*)block.Data(), &len, (const unsigned char*)chunk.Data(), chunk.Size())) {
                    ERR_print_errors_fp(stderr);
                    return 1;
                }

                if (len != chunkSize) {
                    std::cerr << "Chunk size mismatch for offset " << offset << ": " << len << " != " << chunkSize << std::endl;
                    return 1;
                }

                if (!CreateFile(tmpPath.string(), len, block.Data())) {
                    return 1;
                }

                if (!dryRun) {
                    dev.Write(offset, len, block.Data());
                    dev.FSync();

                    if (!dev) {
                        std::cerr << "Failed at " << std::to_string(offset) << ": can't write to file" << std::endl;
                        return 1;
                    }
                }
            }
        }

        offset += chunkSize;

        {
            uint64_t tmp(NAC::hton(offset));

            offsetFile.Write(0, sizeof(tmp), (const char*)&tmp);
            offsetFile.FSync();

            if (!offsetFile) {
                std::cerr << "Failed at " << std::to_string(offset) << ": can't save offset" << std::endl;
                return 1;
            }
        }

        if (!allZeroes) {
            if (unlink(tmpPath.c_str()) != 0) {
                perror("unlink");
            }
        }

        processed += chunkSize;

        if ((processed - prevProcessed) >= (1 * 1024 * 1024 * 1024)) {
            prevProcessed = processed;

            const time_t t1(time(nullptr));

            if ((t1 >= prevTime) && ((t1 - prevTime) >= 60)) {
                prevTime = t1;

                long double left((long double)(toProcess - processed) / ((long double)processed / (long double)(t1 - t0)));
                std::string unit("second(s)");

                if (left > 100) {
                    left /= 60;
                    unit = "minute(s)";

                    if (left > 90) {
                        left /= 60;
                        unit = "hour(s)";

                        if (left > 30) {
                            left /= 24;
                            unit = "day(s)";
                        }
                    }
                }

                std::cerr << left << " " << unit << " left" << std::endl;
            }
        }
    }

    {
        int len(0);

        if (1 != EVPFinalWrapper(mode, ctx, (unsigned char*)block.Data(), &len)) {
            ERR_print_errors_fp(stderr);
            return 1;
        }

        if (len > 0) {
            const auto tmpPath = wd / (modeName + "_chunk-" + std::to_string(offset) + ".final");

            if (!CreateFile(tmpPath.string(), len, block.Data())) {
                return 1;
            }
        }
    }

    std::cerr << "Success!" << std::endl;

    return 0;
}
