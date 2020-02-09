#include "stdafx.h"
#include <string>
#include <vector>
#include <memory>
#include <iterator>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>

using u8 = unsigned char;
using u32 = unsigned int;
using u16 = unsigned short int;

namespace CpeDumper
{
    class Exception : public std::exception
    {
    public:
        Exception(const std::string& s)
            : std::exception(s.c_str()) {}
    };

    class FileStream
    {
    public:
        enum class ReadMode
        {
            ReadOnly,
            ReadWrite
        };

        // Read any fundamental type
        template<class T>
        void Read(T& type)
        {
            static_assert(std::is_fundamental<T>::value, "Can only read fundamental types");
            ReadBytes(reinterpret_cast<u8*>(&type), sizeof(type));
        }

        // Read a string
        void Read(std::string& type)
        {
            ReadBytes(reinterpret_cast<u8*>(&type[0]), type.size());
        }

        // Read any vector of fundamental type
        template<class T>
        void Read(std::vector<T>& type)
        {
            static_assert(std::is_fundamental<T>::value, "Can only read vectors of fundamental types");
            ReadBytes(reinterpret_cast<u8*>(type.data()), sizeof(T)*type.size());
        }

        // Read any std::array of fundamental type
        template<class T, std::size_t count>
        void Read(std::array<T, count>& type)
        {
            static_assert(std::is_fundamental<T>::value, "Can only read vectors of fundamental types");
            ReadBytes(reinterpret_cast<u8*>(type.data()), sizeof(T)*type.size());
        }

        // Read any fixed array of fundamental type
        template<typename T, std::size_t count>
        void Read(T(&value)[count])
        {
            static_assert(std::is_fundamental<T>::value, "Can only read fundamental types");
            ReadBytes(reinterpret_cast<u8*>(&value[0]), sizeof(T)* count);
        }

        // Write any fundamental type
        template<class T>
        void Write(const T& type)
        {
            static_assert(std::is_fundamental<T>::value, "Can only write fundamental types");
            WriteBytes(reinterpret_cast<const u8*>(&type), sizeof(type));
        }

        // Write vector of any fundamental type
        template<class T>
        void Write(std::vector<T>& type)
        {
            static_assert(std::is_fundamental<T>::value, "Can only write vectors of fundamental types");
            WriteBytes(reinterpret_cast<u8*>(type.data()), sizeof(T)*type.size());
        }

        // Write a string
        void Write(const std::string& type)
        {
            WriteBytes(reinterpret_cast<const u8*>(&type[0]), type.size());
        }

        FileStream(const std::string& fileName, ReadMode mode)
            : mMode(mode), mName(fileName)
        {
            std::ios_base::openmode flags = std::ios::binary | std::ios::ate;
            if (mMode == ReadMode::ReadOnly)
            {
                flags |= std::ios::in;
            }
            else if (mMode == ReadMode::ReadWrite)
            {
                flags |= std::ios::in | std::ios::out | std::ios::trunc;
            }

            mStream.open(fileName.c_str(), flags);
            if (!mStream)
            {
                throw Exception("File I/O error: " + fileName + " mode: " + std::to_string(static_cast<u32>(mode)));
            }

            mSize = static_cast<size_t>(mStream.tellg());
            mStream.seekg(std::ios::beg);
        }

        void ReadBytes(u8* pDest, size_t destSize)
        {
            if (!mStream.read(reinterpret_cast<char*>(pDest), destSize))
            {
                throw Exception("ReadBytes failure");
            }
        }

        void WriteBytes(const u8* pSrc, size_t srcSize)
        {
            if (!mStream.write(reinterpret_cast<const char*>(pSrc), srcSize))
            {
                throw Exception("WriteBytes failure");
            }
        }

        void Write(const char* pSrc, size_t srcSize)
        {
            WriteBytes(reinterpret_cast<const u8*>(pSrc), srcSize);
        }

        void Seek(size_t pos)
        {
            if (!mStream.seekg(pos))
            {
                throw Exception("Seek get failure");
            }

            if (!mStream.seekp(pos))
            {
                throw Exception("Seek put failure");
            }
        }

        bool AtEnd() const
        {
            const int c = mStream.peek();
            return (c == EOF);
        }

        std::string LoadAllToString()
        {
            Seek(0);
            std::string content
            {
                std::istreambuf_iterator<char>(mStream),
                std::istreambuf_iterator<char>()
            };
            return content;
        }

        size_t Pos() const
        {
            return static_cast<size_t>(mStream.tellg());
        }

        size_t Size() const
        {
            return mSize;
        }

    private:
        mutable std::fstream mStream;
        size_t mSize = 0;
        std::string mName;
        ReadMode mMode = ReadMode::ReadOnly;
    };
}


const static u32 kCpeMagic = 0x01455043; // CPE\x1
const static u32 kSectorSize = 2048;

struct PSExeHeader
{
    char id[8]; // "PS-X EXE" or "SCE EXE"
    u32 text;    // SCE exe only
    u32 data;    // SCE exe only
    u32 pc0;
    u32 gp0;     // SCE exe only
    u32 t_addr;
    u32 t_size;
    u32 d_addr;  // SCE exe only
    u32 d_size;  // SCE exe only
    u32 b_addr;  // SCE exe only
    u32 b_size;  // SCE exe only
    u32 s_addr = 0x801FFFF0;
    u32 s_size;

    // Saved by the Exec() system call for returning back to the parent binary
    u32 SavedSP;
    u32 SavedFP;
    u32 SavedGP;
    u32 SavedRA;
    u32 SavedS0;
    char licenseString[200];

    void Write(CpeDumper::FileStream& s)
    {
        s.Write(id, 8);
        s.Write(text);
        s.Write(data);
        s.Write(pc0);
        s.Write(gp0);
        s.Write(t_addr);
        s.Write(t_size);
        s.Write(d_addr);
        s.Write(d_size);
        s.Write(b_addr);
        s.Write(b_size);
        s.Write(s_addr);
        s.Write(s_size);
        s.Write(SavedSP);
        s.Write(SavedFP);
        s.Write(SavedGP);
        s.Write(SavedRA);
        s.Write(SavedS0);
        s.Write(licenseString, 200);
    }
};

const static char kPsxExe[] = "PS-X EXE";
const static char kJpLic[] = "Sony Computer Entertainment Inc. for Japan area";

class CpeFile
{
public:
    explicit CpeFile(const std::string& input)
        : mFileStream(input, CpeDumper::FileStream::ReadMode::ReadOnly)
    {
    }

    int ConvertToPSXExe(const char* fileName)
    {
        std::map<u32, std::vector<u8>> loadDataMap;

        u32 magic = 0;
        mFileStream.Read(magic);
        if (magic != kCpeMagic)
        {
            return 1;
        }

        u32 baseAddress = 0;
        u32 pcReg = 0;
        u32 totalTextSectionLen = 0;

        bool eofChunk = false;
        while (!eofChunk)
        {
            u8 cpeChunkType = 0;
            mFileStream.Read(cpeChunkType);
            switch (cpeChunkType)
            {
            case 0x00: // EOF
                eofChunk = true;
                std::cout << "EOF" << std::endl;
                WriteExe(fileName, pcReg, baseAddress, loadDataMap);
                break;

            case 0x01: // Load data
            {
                u32 addr = 0;
                mFileStream.Read(addr);

                // The lowest starting data is the base address
                if (baseAddress == 0 || addr < baseAddress)
                {
                    baseAddress = addr;
                }

                u32 size = 0;
                mFileStream.Read(size);
                totalTextSectionLen += size;

                std::vector<u8> data(size);
                mFileStream.Read(data);

                loadDataMap[addr] = std::move(data);

                std::cout << "Load data addr 0x" << std::hex << addr << " len " << std::dec << size << std::endl;

            }
            break;

            case 0x02: // Run address/entry point
            {
                u16 reg = 0;
                mFileStream.Read(reg);
                std::cout << "Run address" << std::endl;
            }
            break;

            case 0x03: // Set Reg X to longword y (32bit) (LEN=4)
            {
                u16 reg = 0;
                mFileStream.Read(reg);

                u32 val = 0;
                mFileStream.Read(val);

                if (reg == 0x0090)
                {
                    pcReg = val;
                    std::cout << "Program counter 0x" << std::hex << val << std::dec << std::endl;

                }
                else
                {
                    std::cout << "Set Reg long " << reg << " val 0x" << std::hex << val << std::dec << std::endl;
                }
            }
            break;

            case 0x04: // Set Reg X to word y     (16bit) (LEN=2)
            {
                u16 reg = 0;
                mFileStream.Read(reg);

                u16 val = 0;
                mFileStream.Read(val);

                std::cout << "Set Reg word" << std::endl;
            }
            break;

            case 0x05: // Set Reg X to byte y     (8bit) (LEN=1)
            {
                u16 reg = 0;
                mFileStream.Read(reg);

                u8 val = 0;
                mFileStream.Read(val);

                std::cout << "Set Reg byte" << std::endl;
            }
            break;

            case 0x06: // Set Reg X to triplet y  (24bit) (LEN=3)
            {
                u16 reg = 0;
                mFileStream.Read(reg);

                u8 val[3] = {};
                mFileStream.Read(val);

                std::cout << "Set Reg triplet" << std::endl;
            }
            break;

            case 0x07: // Select workspace
            {
                u32 workspace = 0;
                mFileStream.Read(workspace);
                std::cout << "Select workspace " << workspace << std::endl;
            }
            break;

            case 0x08: // Select unit
            {
                u8 unit = 0;
                mFileStream.Read(unit);
                std::cout << "Select unit " << static_cast<u32>(unit) << std::endl;
            }
            break;

            default:
                std::cout << "Unknown " << static_cast<u32>(cpeChunkType) << std::endl;
                break;
            }
        }
        return 0;
    }

private:
    void ValidateProgramCounter(u32 pcReg)
    {
        const static u32 kBiosReserved = 64 * 1024;
        const static u32 k2MbRam = 2048 * 1024;
        const static u32 k8MbRam = 8192 * 1024;

        if (
            // Main ram - assume 2MB (can be modded up to 8MB)
            (pcReg >= 0x0 + kBiosReserved && pcReg <= 0x0 + k2MbRam) ||
            (pcReg >= 0x80000000 + kBiosReserved && pcReg <= 0x80000000 + k2MbRam) ||
            (pcReg >= 0xA0000000 + kBiosReserved && pcReg <= 0xA0000000 + k2MbRam) ||

            // Expansion Region 1 - assume 8MB (max)
            (pcReg >= 0x1F000000 && pcReg <= 0x1F000000 + k8MbRam) ||
            (pcReg >= 0x9F000000 && pcReg <= 0x9F000000 + k8MbRam) ||
            (pcReg >= 0xBF000000 && pcReg <= 0xBF000000 + k8MbRam) ||

            // Expansion Region 3 - assume 2MB (max)
            (pcReg >= 0x1FA00000 && pcReg <= 0x1FA00000 + k2MbRam) ||
            (pcReg >= 0x9FA00000 && pcReg <= 0x9FA00000 + k2MbRam) ||
            (pcReg >= 0xBFA00000 && pcReg <= 0xBFA00000 + k2MbRam)
            )
        {
            // Seems to fall within a known valid range
        }
        else
        {
            std::cout << "WARNING: Program counter value doesn't appear in a valid memory range 0x" << std::hex << pcReg << std::endl;
        }
    }

    void WriteExe(const char* fileName, u32 pcReg, u32 baseAddress, const std::map<u32, std::vector<u8>>& offsetToRawDataBlocks)
    {
        PSExeHeader header = {};
        memcpy(&header.id, kPsxExe, sizeof(kPsxExe));
        memcpy(header.licenseString, kJpLic, sizeof(kJpLic));

        header.t_addr = baseAddress;
        header.pc0 = pcReg;

        // TODO: Validate base address
        // TODO: Validate total output size is <= 8 MB, if not then print biggest diff between sections

        CpeDumper::FileStream fs(fileName, CpeDumper::FileStream::ReadMode::ReadWrite);

        u32 fileSize = 0;
        for (const auto& item : offsetToRawDataBlocks)
        {
            // All data starts in sector 1 as sector 0 contains the PSX-EXE header
            const u32 targetPos = (item.first - baseAddress) + kSectorSize;
            if (targetPos >= 0x800000)
            {
                // Over 8 MB - can't be right!
                abort();
            }

            std::cout << "Write " << item.second.size() << " bytes to " << targetPos << std::endl;
            fs.Seek(targetPos);
            fs.WriteBytes(item.second.data(), item.second.size());
            if (targetPos + item.second.size() > fileSize)
            {
                fileSize = targetPos + item.second.size();
            }
        }

        // Write any required padding to make the entire file a multiple of kSectorSize
        if (fileSize %  kSectorSize)
        {
            u8 pad = 0;
            fileSize = (((fileSize / kSectorSize) + 1) * kSectorSize);
            fs.Seek(fileSize - 1);
            fs.Write(pad);
        }
        header.t_size = fileSize - kSectorSize;

        fs.Seek(0);
        header.Write(fs);

        ValidateProgramCounter(pcReg);
    }

    CpeDumper::FileStream mFileStream;

};

int main()
{
    try
    {
        std::string input("test2.cpe");
        CpeFile cpeFile(input);
        return cpeFile.ConvertToPSXExe("output.exe");
    }
    catch (const std::exception e)
    {
        std::cout << "Exception: " << e.what() << std::endl;
        return 1;
    }
}
