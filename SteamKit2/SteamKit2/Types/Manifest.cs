/*
 * This file is subject to the terms and conditions defined in
 * file 'license.txt', which is part of this source code package.
 */

using ProtoBuf;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using ProtoBuf.Meta;

namespace SteamKit2
{

    /// <summary>
    /// 
    /// </summary>
    public class Manifest
    {
        private const int ProtobufPayloadMagic = 0x71F617D0;
        private const int ProtobufMetadataMagic = 0x1F4812BE;
        private const int ProtobufSignatureMagic = 0x1B81B817;
        private const int ProtobufEndofmanifestMagic = 0x32C415AB;

        private Payload _payload;
        private Metadata _metadata;
        private Signature _signature;

        /// <summary>
        /// returns all mappings except those with EDepotFileFlag.Directory flag
        /// </summary>
        public List<FileMapping> Files =>_payload.Mappings.Where(x => x.Flags.HasFlag(EDepotFileFlag.Directory) == false).ToList();
        /// <summary>
        /// returns mappings with EDepotFileFlag.Directory flag
        /// </summary>
        public List<FileMapping> Directories => _payload.Mappings.Where(x => x.Flags.HasFlag(EDepotFileFlag.Directory)).ToList();
        /// <summary>
        /// returns mappings with EDepotFileFlag.InstallScript flag
        /// </summary>
        public List<FileMapping> InstallScripts => _payload.Mappings.Where(x => x.Flags.HasFlag(EDepotFileFlag.InstallScript)).ToList();


        
        /// <summary>
        /// Load manifest from byte array
        /// </summary>
        /// <param name="data"></param>
        public Manifest(byte[] data)
        {
            ReadManifestData(data);
        }

        /// <summary>
        /// Load manifest from file
        /// </summary>
        /// <param name="path"></param>
        /// <exception cref="FileNotFoundException"></exception>
        public Manifest(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException($"Manifest file not found at '{path}'", path);

            ReadManifestData(File.ReadAllBytes(path));
        }

        private void ReadManifestData(byte[] data)
        {
            using (var reader = new MemoryStream(data))
            {

                while (reader.Position < reader.Length)
                {
                    var magic = reader.ReadInt32();

                    switch (magic)
                    {
                        case ProtobufPayloadMagic:
                            var payloadLength = reader.ReadUInt32();
                            var payloadBytes = reader.ReadBytes((int)payloadLength);
                            using (var msPayload = new MemoryStream(payloadBytes))
                                _payload = Serializer.Deserialize<Payload>(msPayload);

                            break;
                        case ProtobufMetadataMagic:
                            var metadataLength = reader.ReadUInt32();
                            var metadataBytes = reader.ReadBytes((int)metadataLength);
                            using (var msMetadata = new MemoryStream(metadataBytes))
                                _metadata = Serializer.Deserialize<Metadata>(msMetadata);
                            break;

                        case ProtobufSignatureMagic:
                            var signatureLength = reader.ReadUInt32();
                            var signatureBytes = reader.ReadBytes((int)signatureLength);
                            using (var msSignature = new MemoryStream(signatureBytes))
                                _signature = Serializer.Deserialize<Signature>(msSignature);
                            break;

                        case ProtobufEndofmanifestMagic:
                            break;

                        default:
                            throw new Exception(string.Format("Unrecognized magic value {0:X} in depot manifest.", magic));
                    }
                }

            }
        }

        
        /// <summary>
        /// Decrypts filenames 
        /// </summary>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public bool DecryptFilenames(byte[] encryptionKey)
        {
            if (!_metadata.FilenamesEncrypted)
                return true;

            foreach (var file in _payload.Mappings)
            {
                byte[] encodedFilename = Convert.FromBase64String(file.FileName);
                byte[] filename;
                try
                {
                    filename = CryptoHelper.SymmetricDecrypt(encodedFilename, encryptionKey);
                }
                catch (Exception)
                {
                    return false;
                }

                file.FileName = Encoding.UTF8.GetString(filename).TrimEnd('\0');
            }

            _metadata.FilenamesEncrypted = false;
            return true;
        }

        
        /// <summary>
        /// Write manifest to file
        /// </summary>
        /// <param name="path"></param>
        /// <param name="stripSignature"></param>
        public void Save(string path, bool stripSignature = true)
        {
            if (stripSignature)
                _signature.Data = null;

            new FileInfo(path).Directory?.Create();

            path = path.Replace("\\", "/");
            using (var fs = File.Open(path, FileMode.Create, FileAccess.Write))
            {
                _payload.WriteToStream(fs);
                _metadata.WriteToStream(fs, _payload);
                _signature.WriteToStream(fs);
            }
        }

        #region PROTOBUF CLASSES

        [ProtoContract()]
        internal class Payload
        {


            [ProtoMember(1)]
            public List<FileMapping> Mappings { get; set; }

            public uint CrcClear;

            public Payload() { }

            public void WriteToStream(Stream stream)
            {

                RuntimeTypeModel typeModel = TypeModel.Create();
                typeModel.UseImplicitZeroDefaults = false;
                Mappings.Sort((x, y) => string.Compare(x.FileName, y.FileName, StringComparison.OrdinalIgnoreCase));
                using (var memStream = new MemoryStream())
                {
                    typeModel.Serialize(memStream, this);
                    int length = (int)memStream.Length;
                    using (MemoryStream ms = new MemoryStream())
                    {
                        ms.Write(BitConverter.GetBytes(length), 0, 4);
                        ms.Write(memStream.ToArray(), 0, length);
                        CrcClear = (uint)Crc32.Compute(ms.ToArray());
                    }
                    stream.Write(new byte[] { 0xd0, 0x17, 0xf6, 0x71 }, 0, 4);
                    stream.Write(BitConverter.GetBytes(length), 0, 4);
                    stream.Write(memStream.ToArray(), 0, length);
                }
            }



        }

        /// <summary>
        /// Manifest FileMapping
        /// </summary>
        [ProtoContract()]
        public class FileMapping
        {
            /// <inheritdoc />
            public FileMapping()
            {
            }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(1)]
            public string FileName { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(2)]
            public ulong Size { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(3)]
            public EDepotFileFlag Flags { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(4)]
            public byte[] ShaFilename { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(5)]
            public byte[] ShaContent { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(6)]
            public List<ChunkData> Chunks { get; set; }

            /// <summary>
            /// 
            /// </summary>
            public bool Valid { get; set; }

            /// <summary>
            /// 
            /// </summary>
            public uint ParentDepotId;

            /// <inheritdoc />
            public override string ToString()
            {
                return FileName;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        [ProtoContract()]
        public class ChunkData
        {
            /// <inheritdoc />
            public ChunkData()
            {
            }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(1)]
            public byte[] Sha { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(2, DataFormat = DataFormat.FixedSize)]
            public uint Adler32 { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(3)]
            public ulong Offset { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(4)]
            public uint Size { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [ProtoMember(5)]
            public uint CompressedSize { get; set; }

            /// <summary>
            /// 
            /// </summary>
            public bool Valid { get; set; } = false;
            /// <summary>
            /// 
            /// </summary>
            public FileMapping ParentMapping { get; set; }
        }

        [ProtoContract()]
        private class Metadata
        {

            public void WriteToStream(Stream stream, Payload payload)
            {
                CrcClear = payload.CrcClear;
                //RuntimeTypeModel typeModel = TypeModel.Create();
                //typeModel.UseImplicitZeroDefaults = false;
                using (var memStream = new MemoryStream())
                {
                    Serializer.Serialize(memStream, this);
                    //typeModel.Serialize(memStream, this);
                    int length = (int)memStream.Length;
                    stream.Write(new byte[] { 0xbe, 0x12, 0x48, 0x1f }, 0, 4);
                    stream.Write(BitConverter.GetBytes(length), 0, 4);
                    stream.Write(memStream.ToArray(), 0, length);
                }
            }

            [ProtoMember(1, IsRequired = true)]
            public uint DepotId { get; set; }
            [ProtoMember(2, IsRequired = true)]
            public ulong GidManifest { get; set; }
            [ProtoMember(3, IsRequired = true)]
            public uint CreationTime { get; set; }
            [ProtoMember(4, IsRequired = true)]
            public bool FilenamesEncrypted { get; set; }
            [ProtoMember(5, IsRequired = true)]
            public ulong SizeOnDisk { get; set; }
            [ProtoMember(6, IsRequired = true)]
            public ulong CompressedSizeOnDisk { get; set; }
            [ProtoMember(7, IsRequired = true)]
            public uint UniqueChunks { get; set; }
            [ProtoMember(8)]
            public uint CrcEncrypted { get; set; }
            [ProtoMember(9)]
            public uint CrcClear { get; set; }
        }

        [ProtoContract()]
        private class Signature
        {
            public void WriteToStream(Stream stream)
            {
                RuntimeTypeModel typeModel = TypeModel.Create();
                typeModel.UseImplicitZeroDefaults = false;

                using (var memStream = new MemoryStream())
                {
                    typeModel.Serialize(memStream, this);
                    stream.Write(new byte[] { 0x17, 0xB8, 0x81, 0x1B }, 0, 4);
                    if (Data != null && Data.Length > 0)
                    {
                        stream.Write(BitConverter.GetBytes(Data.Length), 0, 4);
                        stream.Write(Data, 0, Data.Length);
                    }
                    else
                    {
                        stream.Write(BitConverter.GetBytes(0), 0, 4);

                    }

                    stream.Write(new byte[] { 0xAB, 0x15, 0xC4, 0x32 }, 0, 4);
                }
            }


            [ProtoMember(1)]
            public byte[] Data { get; set; }
        }
        #endregion
    }
}
