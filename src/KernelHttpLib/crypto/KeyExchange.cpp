#include <KernelHttp/crypto/KeyExchange.h>
#include <KernelHttp/crypto/CngProviderCache.h>

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T FieldElementLength = 16;
        using FieldElement = long long[FieldElementLength];
        constexpr SIZE_T X25519ProductLength = 31;

        const UCHAR X25519BasePoint[KeyExchangeX25519KeyLength] = {
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        const UCHAR X448BasePoint[KeyExchangeX448KeyLength] = {
            5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        const FieldElement Field121665 = {
            0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        const UCHAR FfdheGeneratorTwo[1] = { 2 };

        struct X25519Scratch final
        {
            UCHAR Scalar[KeyExchangeX25519KeyLength] = {};
            long long Product[X25519ProductLength] = {};
            long long Value[FieldElementLength] = {};
            long long Reduced[FieldElementLength] = {};
            long long X[FieldElementLength] = {};
            long long A[FieldElementLength] = {};
            long long B[FieldElementLength] = {};
            long long C[FieldElementLength] = {};
            long long D[FieldElementLength] = {};
            long long E[FieldElementLength] = {};
            long long F[FieldElementLength] = {};
        };

        class X25519ScratchGuard final
        {
        public:
            X25519ScratchGuard() noexcept = default;

            ~X25519ScratchGuard() noexcept
            {
                if (scratch_.IsValid()) {
                    RtlSecureZeroMemory(scratch_.Get(), sizeof(X25519Scratch));
                }
            }

            X25519ScratchGuard(const X25519ScratchGuard&) = delete;
            X25519ScratchGuard& operator=(const X25519ScratchGuard&) = delete;

            _Must_inspect_result_
            bool IsValid() const noexcept
            {
                return scratch_.IsValid();
            }

            X25519Scratch& Get() noexcept
            {
                return *scratch_.Get();
            }

        private:
            HeapObject<X25519Scratch> scratch_;
        };

        constexpr SIZE_T X448LimbCount = KeyExchangeX448KeyLength / sizeof(ULONG);
        constexpr SIZE_T X448ProductCount = (X448LimbCount * 2) + 1;
        constexpr SIZE_T X448FieldBlockCount = 23;
        constexpr ULONG X448A24 = 39081;

        constexpr char X448PrimeHex[] =
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

        constexpr char X448PrimeMinusTwoHex[] =
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD";

        struct FfdheGroupParameters final
        {
            KeyExchangeGroup Group = KeyExchangeGroup::Ffdhe2048;
            const char* ModulusHex = nullptr;
            SIZE_T ModulusLength = 0;
            SIZE_T PrivateExponentLength = 0;
        };

        constexpr char Ffdhe2048ModulusHex[] =
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
            "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
            "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
            "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
            "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
            "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

        constexpr char Ffdhe3072ModulusHex[] =
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
            "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
            "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
            "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
            "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
            "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
            "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
            "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
            "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";

        constexpr char Ffdhe4096ModulusHex[] =
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
            "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
            "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
            "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
            "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
            "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
            "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
            "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
            "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A"
            "7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038"
            "092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF";

        constexpr char Ffdhe6144ModulusHex[] =
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
            "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
            "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
            "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
            "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
            "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
            "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
            "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
            "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A"
            "7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038"
            "092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A"
            "4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4C"
            "B38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"
            "A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E"
            "7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992"
            "EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"
            "D72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B9117"
            "8CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E69"
            "62A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF";

        constexpr char Ffdhe8192ModulusHex[] =
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
            "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
            "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
            "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
            "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
            "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
            "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
            "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
            "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A"
            "7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038"
            "092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A"
            "4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4C"
            "B38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"
            "A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E"
            "7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992"
            "EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"
            "D72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B9117"
            "8CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E69"
            "62A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838"
            "1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF"
            "86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E4"
            "54504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022"
            "BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC"
            "99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E231"
            "83F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30"
            "FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D"
            "0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF";

        const FfdheGroupParameters FfdheGroups[] = {
            { KeyExchangeGroup::Ffdhe2048, Ffdhe2048ModulusHex, KeyExchangeFfdhe2048Length, 32 },
            { KeyExchangeGroup::Ffdhe3072, Ffdhe3072ModulusHex, KeyExchangeFfdhe3072Length, 40 },
            { KeyExchangeGroup::Ffdhe4096, Ffdhe4096ModulusHex, KeyExchangeFfdhe4096Length, 48 },
            { KeyExchangeGroup::Ffdhe6144, Ffdhe6144ModulusHex, KeyExchangeFfdhe6144Length, 48 },
            { KeyExchangeGroup::Ffdhe8192, Ffdhe8192ModulusHex, KeyExchangeFfdhe8192Length, 56 }
        };

        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool IsAllZero(_In_reads_bytes_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | data[index]);
            }
            return diff == 0;
        }

        _Must_inspect_result_
        bool IsFfdheGroup(KeyExchangeGroup group) noexcept
        {
            return group == KeyExchangeGroup::Ffdhe2048 ||
                group == KeyExchangeGroup::Ffdhe3072 ||
                group == KeyExchangeGroup::Ffdhe4096 ||
                group == KeyExchangeGroup::Ffdhe6144 ||
                group == KeyExchangeGroup::Ffdhe8192;
        }

        _Ret_maybenull_
        const FfdheGroupParameters* FindFfdheGroup(KeyExchangeGroup group) noexcept
        {
            for (SIZE_T index = 0; index < sizeof(FfdheGroups) / sizeof(FfdheGroups[0]); ++index) {
                if (FfdheGroups[index].Group == group) {
                    return &FfdheGroups[index];
                }
            }
            return nullptr;
        }

        _Must_inspect_result_
        int HexValue(char value) noexcept
        {
            if (value >= '0' && value <= '9') {
                return value - '0';
            }
            if (value >= 'A' && value <= 'F') {
                return value - 'A' + 10;
            }
            if (value >= 'a' && value <= 'f') {
                return value - 'a' + 10;
            }
            return -1;
        }

        _Must_inspect_result_
        NTSTATUS ParseHexToBytes(
            _In_z_ const char* hex,
            _Out_writes_bytes_(destinationLength) UCHAR* destination,
            SIZE_T destinationLength) noexcept
        {
            if (hex == nullptr || destination == nullptr || destinationLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T hexLength = 0;
            while (hex[hexLength] != '\0') {
                ++hexLength;
            }

            if (hexLength != destinationLength * 2) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < destinationLength; ++index) {
                const int high = HexValue(hex[index * 2]);
                const int low = HexValue(hex[(index * 2) + 1]);
                if (high < 0 || low < 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                destination[index] = static_cast<UCHAR>((high << 4) | low);
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        int CompareBigEndian(
            _In_reads_bytes_(length) const UCHAR* left,
            _In_reads_bytes_(length) const UCHAR* right,
            SIZE_T length) noexcept
        {
            for (SIZE_T index = 0; index < length; ++index) {
                if (left[index] < right[index]) {
                    return -1;
                }
                if (left[index] > right[index]) {
                    return 1;
                }
            }
            return 0;
        }

        _Must_inspect_result_
        bool IsBigEndianOne(_In_reads_bytes_(length) const UCHAR* value, SIZE_T length) noexcept
        {
            if (value == nullptr || length == 0 || value[length - 1] != 1) {
                return false;
            }
            for (SIZE_T index = 0; index + 1 < length; ++index) {
                if (value[index] != 0) {
                    return false;
                }
            }
            return true;
        }

        _Must_inspect_result_
        NTSTATUS NormalizeFfdhePublicKey(
            _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
            SIZE_T publicKeyLength,
            _Out_writes_bytes_(normalizedLength) UCHAR* normalized,
            SIZE_T normalizedLength) noexcept
        {
            if (publicKey == nullptr || publicKeyLength == 0 || normalized == nullptr || normalizedLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            while (publicKeyLength > 0 && publicKey[0] == 0) {
                ++publicKey;
                --publicKeyLength;
            }

            if (publicKeyLength == 0 || publicKeyLength > normalizedLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            RtlZeroMemory(normalized, normalizedLength);
            RtlCopyMemory(normalized + (normalizedLength - publicKeyLength), publicKey, publicKeyLength);
            return STATUS_SUCCESS;
        }

        void SubtractOneBigEndian(_Inout_updates_(length) UCHAR* value, SIZE_T length) noexcept
        {
            for (SIZE_T remaining = length; remaining > 0; --remaining) {
                const SIZE_T index = remaining - 1;
                if (value[index] != 0) {
                    --value[index];
                    return;
                }
                value[index] = 0xff;
            }
        }

        _Must_inspect_result_
        NTSTATUS ValidateFfdhePublicKeyWithParameters(
            _In_ const FfdheGroupParameters& parameters,
            _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
            SIZE_T publicKeyLength) noexcept
        {
            HeapArray<UCHAR> modulus(parameters.ModulusLength);
            HeapArray<UCHAR> upperBound(parameters.ModulusLength);
            HeapArray<UCHAR> normalized(parameters.ModulusLength);
            if (!modulus.IsValid() || !upperBound.IsValid() || !normalized.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = ParseHexToBytes(parameters.ModulusHex, modulus.Get(), modulus.Count());
            if (NT_SUCCESS(status)) {
                status = NormalizeFfdhePublicKey(
                    publicKey,
                    publicKeyLength,
                    normalized.Get(),
                    normalized.Count());
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            RtlCopyMemory(upperBound.Get(), modulus.Get(), modulus.Count());
            SubtractOneBigEndian(upperBound.Get(), upperBound.Count());

            if (IsAllZero(normalized.Get(), normalized.Count()) ||
                IsBigEndianOne(normalized.Get(), normalized.Count()) ||
                CompareBigEndian(normalized.Get(), upperBound.Get(), normalized.Count()) >= 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            return STATUS_SUCCESS;
        }

        void AddFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement left,
            _In_reads_(FieldElementLength) const FieldElement right) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = left[index] + right[index];
            }
        }

        void SubtractFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement left,
            _In_reads_(FieldElementLength) const FieldElement right) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = left[index] - right[index];
            }
        }

        void CarryFieldElement(_Inout_updates_(FieldElementLength) FieldElement value) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                value[index] += 1LL << 16;
                const long long carry = value[index] >> 16;
                if (index < FieldElementLength - 1) {
                    value[index + 1] += carry - 1;
                }
                else {
                    value[0] += 38 * (carry - 1);
                }
                value[index] -= carry << 16;
            }
        }

        void SelectFieldElement(
            _Inout_updates_(FieldElementLength) FieldElement left,
            _Inout_updates_(FieldElementLength) FieldElement right,
            long long swap) noexcept
        {
            const long long mask = ~(swap - 1);
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                const long long value = mask & (left[index] ^ right[index]);
                left[index] ^= value;
                right[index] ^= value;
            }
        }

        void CopyFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = input[index];
            }
        }

        void MultiplyFieldElement(
            _Inout_ X25519Scratch& scratch,
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement left,
            _In_reads_(FieldElementLength) const FieldElement right) noexcept
        {
            long long* product = scratch.Product;
            RtlZeroMemory(product, sizeof(scratch.Product));
            for (SIZE_T leftIndex = 0; leftIndex < FieldElementLength; ++leftIndex) {
                for (SIZE_T rightIndex = 0; rightIndex < FieldElementLength; ++rightIndex) {
                    product[leftIndex + rightIndex] += left[leftIndex] * right[rightIndex];
                }
            }

            for (SIZE_T index = 0; index < FieldElementLength - 1; ++index) {
                product[index] += 38 * product[index + FieldElementLength];
            }
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = product[index];
            }

            CarryFieldElement(output);
            CarryFieldElement(output);
            RtlSecureZeroMemory(product, sizeof(scratch.Product));
        }

        void SquareFieldElement(
            _Inout_ X25519Scratch& scratch,
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            MultiplyFieldElement(scratch, output, input, input);
        }

        void UnpackFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_bytes_(KeyExchangeX25519KeyLength) const UCHAR* input) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] =
                    static_cast<long long>(input[2 * index]) |
                    (static_cast<long long>(input[(2 * index) + 1]) << 8);
            }
            output[15] &= 0x7fff;
        }

        void PackFieldElement(
            _Inout_ X25519Scratch& scratch,
            _Out_writes_bytes_(KeyExchangeX25519KeyLength) UCHAR* output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            FieldElement& value = scratch.Value;
            FieldElement& reduced = scratch.Reduced;
            RtlZeroMemory(value, sizeof(scratch.Value));
            RtlZeroMemory(reduced, sizeof(scratch.Reduced));
            CopyFieldElement(value, input);
            CarryFieldElement(value);
            CarryFieldElement(value);
            CarryFieldElement(value);

            for (SIZE_T round = 0; round < 2; ++round) {
                CopyFieldElement(reduced, value);
                reduced[0] -= 0xffed;
                for (SIZE_T index = 1; index < FieldElementLength - 1; ++index) {
                    reduced[index] -= 0xffff + ((reduced[index - 1] >> 16) & 1);
                    reduced[index - 1] &= 0xffff;
                }
                reduced[15] -= 0x7fff + ((reduced[14] >> 16) & 1);
                reduced[14] &= 0xffff;
                SelectFieldElement(value, reduced, 1 - ((reduced[15] >> 16) & 1));
            }

            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[2 * index] = static_cast<UCHAR>(value[index] & 0xff);
                output[(2 * index) + 1] = static_cast<UCHAR>((value[index] >> 8) & 0xff);
            }

            RtlSecureZeroMemory(value, sizeof(scratch.Value));
            RtlSecureZeroMemory(reduced, sizeof(scratch.Reduced));
        }

        void InvertFieldElement(
            _Inout_ X25519Scratch& scratch,
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            FieldElement& value = scratch.Value;
            RtlZeroMemory(value, sizeof(scratch.Value));
            CopyFieldElement(value, input);
            for (int index = 253; index >= 0; --index) {
                SquareFieldElement(scratch, value, value);
                if (index != 2 && index != 4) {
                    MultiplyFieldElement(scratch, value, value, input);
                }
            }
            CopyFieldElement(output, value);
            RtlSecureZeroMemory(value, sizeof(scratch.Value));
        }

        void ClampX25519Scalar(_Inout_updates_(KeyExchangeX25519KeyLength) UCHAR* scalar) noexcept
        {
            scalar[0] &= 248;
            scalar[31] &= 127;
            scalar[31] |= 64;
        }

        _Must_inspect_result_
        NTSTATUS X25519(
            _In_reads_bytes_(KeyExchangeX25519KeyLength) const UCHAR* privateKey,
            _In_reads_bytes_(KeyExchangeX25519KeyLength) const UCHAR* peerPublicKey,
            _Out_writes_bytes_(KeyExchangeX25519KeyLength) UCHAR* output) noexcept
        {
            if (privateKey == nullptr || peerPublicKey == nullptr || output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (IsAllZero(peerPublicKey, KeyExchangeX25519KeyLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            X25519ScratchGuard scratchGuard;
            if (!scratchGuard.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            X25519Scratch& scratch = scratchGuard.Get();

            UCHAR* scalar = scratch.Scalar;
            RtlCopyMemory(scalar, privateKey, sizeof(scratch.Scalar));
            ClampX25519Scalar(scalar);

            FieldElement& x = scratch.X;
            FieldElement& a = scratch.A;
            FieldElement& b = scratch.B;
            FieldElement& c = scratch.C;
            FieldElement& d = scratch.D;
            FieldElement& e = scratch.E;
            FieldElement& f = scratch.F;
            RtlZeroMemory(x, sizeof(scratch.X));
            RtlZeroMemory(a, sizeof(scratch.A));
            RtlZeroMemory(b, sizeof(scratch.B));
            RtlZeroMemory(c, sizeof(scratch.C));
            RtlZeroMemory(d, sizeof(scratch.D));
            RtlZeroMemory(e, sizeof(scratch.E));
            RtlZeroMemory(f, sizeof(scratch.F));

            UnpackFieldElement(x, peerPublicKey);
            a[0] = 1;
            d[0] = 1;
            CopyFieldElement(b, x);

            for (int bit = 254; bit >= 0; --bit) {
                const long long swap = (scalar[bit >> 3] >> (bit & 7)) & 1;
                SelectFieldElement(a, b, swap);
                SelectFieldElement(c, d, swap);
                AddFieldElement(e, a, c);
                SubtractFieldElement(a, a, c);
                AddFieldElement(c, b, d);
                SubtractFieldElement(b, b, d);
                SquareFieldElement(scratch, d, e);
                SquareFieldElement(scratch, f, a);
                MultiplyFieldElement(scratch, a, c, a);
                MultiplyFieldElement(scratch, c, b, e);
                AddFieldElement(e, a, c);
                SubtractFieldElement(a, a, c);
                SquareFieldElement(scratch, b, a);
                SubtractFieldElement(c, d, f);
                MultiplyFieldElement(scratch, a, c, Field121665);
                AddFieldElement(a, a, d);
                MultiplyFieldElement(scratch, c, c, a);
                MultiplyFieldElement(scratch, a, d, f);
                MultiplyFieldElement(scratch, d, b, x);
                SquareFieldElement(scratch, b, e);
                SelectFieldElement(a, b, swap);
                SelectFieldElement(c, d, swap);
            }

            InvertFieldElement(scratch, c, c);
            MultiplyFieldElement(scratch, a, a, c);
            PackFieldElement(scratch, output, a);

            RtlSecureZeroMemory(scalar, sizeof(scratch.Scalar));
            RtlSecureZeroMemory(x, sizeof(scratch.X));
            RtlSecureZeroMemory(a, sizeof(scratch.A));
            RtlSecureZeroMemory(b, sizeof(scratch.B));
            RtlSecureZeroMemory(c, sizeof(scratch.C));
            RtlSecureZeroMemory(d, sizeof(scratch.D));
            RtlSecureZeroMemory(e, sizeof(scratch.E));
            RtlSecureZeroMemory(f, sizeof(scratch.F));
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        EcCurve ToEcCurve(KeyExchangeGroup group, _Out_ NTSTATUS* status) noexcept
        {
            if (status == nullptr) {
                return EcCurve::P256;
            }

            switch (group) {
            case KeyExchangeGroup::Secp256r1:
                *status = STATUS_SUCCESS;
                return EcCurve::P256;
            case KeyExchangeGroup::Secp384r1:
                *status = STATUS_SUCCESS;
                return EcCurve::P384;
            case KeyExchangeGroup::Secp521r1:
                *status = STATUS_SUCCESS;
                return EcCurve::P521;
            default:
                *status = STATUS_NOT_SUPPORTED;
                return EcCurve::P256;
            }
        }

        _Must_inspect_result_
        SIZE_T ReadLittleEndianUint32(_In_reads_bytes_(sizeof(ULONG)) const UCHAR* data) noexcept
        {
            return static_cast<SIZE_T>(data[0]) |
                (static_cast<SIZE_T>(data[1]) << 8) |
                (static_cast<SIZE_T>(data[2]) << 16) |
                (static_cast<SIZE_T>(data[3]) << 24);
        }

        _Must_inspect_result_
        NTSTATUS ExportNistPublicKey(
            _In_ const CngKey& privateKey,
            _Out_writes_bytes_(publicKeyCapacity) UCHAR* publicKey,
            SIZE_T publicKeyCapacity,
            _Out_ SIZE_T* publicKeyLength) noexcept
        {
            if (publicKeyLength != nullptr) {
                *publicKeyLength = 0;
            }
            if (publicKey == nullptr || publicKeyLength == nullptr || publicKeyCapacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            constexpr SIZE_T EccPublicBlobHeaderLength = sizeof(ULONG) * 2;
            constexpr SIZE_T EccPublicBlobMaxCoordinateLength = 66;

            HeapArray<UCHAR> publicBlob(EccPublicBlobHeaderLength + (EccPublicBlobMaxCoordinateLength * 2));
            if (!publicBlob.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T publicBlobLength = 0;
            NTSTATUS status = privateKey.ExportPublicKey(
                L"ECCPUBLICBLOB",
                publicBlob.Get(),
                publicBlob.Count(),
                &publicBlobLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (publicBlobLength != 0 && publicBlob[0] == 4) {
                if (publicBlobLength != 65 && publicBlobLength != 97 && publicBlobLength != 133) {
                    RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (publicBlobLength > publicKeyCapacity) {
                    RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                    *publicKeyLength = publicBlobLength;
                    return STATUS_BUFFER_TOO_SMALL;
                }

                RtlCopyMemory(publicKey, publicBlob.Get(), publicBlobLength);
                *publicKeyLength = publicBlobLength;
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                return STATUS_SUCCESS;
            }
            if (publicBlobLength < EccPublicBlobHeaderLength) {
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T keyBytes = ReadLittleEndianUint32(publicBlob.Get() + sizeof(ULONG));
            const SIZE_T coordinatesLength = keyBytes * 2;
            const SIZE_T pointLength = coordinatesLength + 1;
            if (keyBytes == 0 ||
                keyBytes > EccPublicBlobMaxCoordinateLength ||
                coordinatesLength > publicBlobLength - EccPublicBlobHeaderLength) {
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (pointLength > publicKeyCapacity) {
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                *publicKeyLength = pointLength;
                return STATUS_BUFFER_TOO_SMALL;
            }

            publicKey[0] = 4;
            RtlCopyMemory(publicKey + 1, publicBlob.Get() + EccPublicBlobHeaderLength, coordinatesLength);
            *publicKeyLength = pointLength;
            RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateX25519Lengths(
            const UCHAR* privateKey,
            SIZE_T privateKeyLength,
            const UCHAR* peerPublicKey,
            SIZE_T peerPublicKeyLength,
            UCHAR* sharedSecret,
            SIZE_T sharedSecretCapacity,
            SIZE_T* sharedSecretLength) noexcept
        {
            if (sharedSecretLength != nullptr) {
                *sharedSecretLength = 0;
            }
            if (privateKey == nullptr ||
                privateKeyLength != KeyExchangeX25519KeyLength ||
                peerPublicKey == nullptr ||
                peerPublicKeyLength != KeyExchangeX25519KeyLength ||
                sharedSecret == nullptr ||
                sharedSecretCapacity < KeyExchangeX25519KeyLength ||
                sharedSecretLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        SIZE_T LimbCountForBytes(SIZE_T byteLength) noexcept
        {
            return (byteLength + sizeof(ULONG) - 1) / sizeof(ULONG);
        }

        void BigEndianToLimbs(
            _In_reads_bytes_(sourceLength) const UCHAR* source,
            SIZE_T sourceLength,
            _Out_writes_(limbCount) ULONG* limbs,
            SIZE_T limbCount) noexcept
        {
            RtlZeroMemory(limbs, limbCount * sizeof(ULONG));
            for (SIZE_T byteIndex = 0; byteIndex < sourceLength; ++byteIndex) {
                const SIZE_T sourceIndex = sourceLength - 1 - byteIndex;
                const SIZE_T limbIndex = byteIndex / sizeof(ULONG);
                const SIZE_T shift = (byteIndex % sizeof(ULONG)) * 8;
                if (limbIndex < limbCount) {
                    limbs[limbIndex] |= static_cast<ULONG>(source[sourceIndex]) << shift;
                }
            }
        }

        void LimbsToBigEndian(
            _In_reads_(limbCount) const ULONG* limbs,
            SIZE_T limbCount,
            _Out_writes_bytes_(destinationLength) UCHAR* destination,
            SIZE_T destinationLength) noexcept
        {
            RtlZeroMemory(destination, destinationLength);
            for (SIZE_T byteIndex = 0; byteIndex < destinationLength; ++byteIndex) {
                const SIZE_T destinationIndex = destinationLength - 1 - byteIndex;
                const SIZE_T limbIndex = byteIndex / sizeof(ULONG);
                const SIZE_T shift = (byteIndex % sizeof(ULONG)) * 8;
                if (limbIndex < limbCount) {
                    destination[destinationIndex] = static_cast<UCHAR>((limbs[limbIndex] >> shift) & 0xff);
                }
            }
        }

        void LittleEndianToLimbs(
            _In_reads_bytes_(sourceLength) const UCHAR* source,
            SIZE_T sourceLength,
            _Out_writes_(limbCount) ULONG* limbs,
            SIZE_T limbCount) noexcept
        {
            RtlZeroMemory(limbs, limbCount * sizeof(ULONG));
            for (SIZE_T byteIndex = 0; byteIndex < sourceLength; ++byteIndex) {
                const SIZE_T limbIndex = byteIndex / sizeof(ULONG);
                const SIZE_T shift = (byteIndex % sizeof(ULONG)) * 8;
                if (limbIndex < limbCount) {
                    limbs[limbIndex] |= static_cast<ULONG>(source[byteIndex]) << shift;
                }
            }
        }

        void LimbsToLittleEndian(
            _In_reads_(limbCount) const ULONG* limbs,
            SIZE_T limbCount,
            _Out_writes_bytes_(destinationLength) UCHAR* destination,
            SIZE_T destinationLength) noexcept
        {
            RtlZeroMemory(destination, destinationLength);
            for (SIZE_T byteIndex = 0; byteIndex < destinationLength; ++byteIndex) {
                const SIZE_T limbIndex = byteIndex / sizeof(ULONG);
                const SIZE_T shift = (byteIndex % sizeof(ULONG)) * 8;
                if (limbIndex < limbCount) {
                    destination[byteIndex] = static_cast<UCHAR>((limbs[limbIndex] >> shift) & 0xff);
                }
            }
        }

        _Must_inspect_result_
        int CompareLimbs(
            _In_reads_(limbCount) const ULONG* left,
            _In_reads_(limbCount) const ULONG* right,
            SIZE_T limbCount) noexcept
        {
            for (SIZE_T remaining = limbCount; remaining > 0; --remaining) {
                const SIZE_T index = remaining - 1;
                if (left[index] < right[index]) {
                    return -1;
                }
                if (left[index] > right[index]) {
                    return 1;
                }
            }
            return 0;
        }

        void SubtractLimbsInPlace(
            _Inout_updates_(limbCount) ULONG* left,
            _In_reads_(limbCount) const ULONG* right,
            SIZE_T limbCount) noexcept
        {
            ULONGLONG borrow = 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONGLONG subtrahend = static_cast<ULONGLONG>(right[index]) + borrow;
                const ULONGLONG minuend = left[index];
                left[index] = static_cast<ULONG>(minuend - subtrahend);
                borrow = minuend < subtrahend ? 1 : 0;
            }
        }

        void LeftShiftOneModulo(
            _Inout_updates_(limbCount) ULONG* value,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount) noexcept
        {
            ULONG carry = 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONG nextCarry = (value[index] >> 31) & 1;
                value[index] = static_cast<ULONG>((value[index] << 1) | carry);
                carry = nextCarry;
            }

            if (carry != 0 || CompareLimbs(value, modulus, limbCount) >= 0) {
                SubtractLimbsInPlace(value, modulus, limbCount);
            }
        }

        _Must_inspect_result_
        ULONG MontgomeryN0Prime(ULONG modulusLow) noexcept
        {
            ULONG inverse = 1;
            for (SIZE_T round = 0; round < 5; ++round) {
                inverse = static_cast<ULONG>(
                    inverse *
                    static_cast<ULONG>(2 - static_cast<ULONG>(modulusLow * inverse)));
            }
            return static_cast<ULONG>(0 - inverse);
        }

        void MultiplyLimbs(
            _In_reads_(limbCount) const ULONG* left,
            _In_reads_(limbCount) const ULONG* right,
            SIZE_T limbCount,
            _Out_writes_(productCount) ULONG* product,
            SIZE_T productCount) noexcept
        {
            RtlZeroMemory(product, productCount * sizeof(ULONG));
            for (SIZE_T leftIndex = 0; leftIndex < limbCount; ++leftIndex) {
                ULONGLONG carry = 0;
                for (SIZE_T rightIndex = 0; rightIndex < limbCount; ++rightIndex) {
                    const SIZE_T productIndex = leftIndex + rightIndex;
                    const ULONGLONG value =
                        static_cast<ULONGLONG>(left[leftIndex]) *
                        static_cast<ULONGLONG>(right[rightIndex]) +
                        static_cast<ULONGLONG>(product[productIndex]) +
                        carry;
                    product[productIndex] = static_cast<ULONG>(value);
                    carry = value >> 32;
                }

                SIZE_T carryIndex = leftIndex + limbCount;
                while (carry != 0 && carryIndex < productCount) {
                    const ULONGLONG value = static_cast<ULONGLONG>(product[carryIndex]) + carry;
                    product[carryIndex] = static_cast<ULONG>(value);
                    carry = value >> 32;
                    ++carryIndex;
                }
            }
        }

        _Must_inspect_result_
        int CompareCandidateToModulus(
            _In_reads_(limbCountPlusOne) const ULONG* candidate,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            SIZE_T limbCountPlusOne) noexcept
        {
            if (limbCountPlusOne != limbCount + 1) {
                return 1;
            }
            if (candidate[limbCount] != 0) {
                return 1;
            }
            return CompareLimbs(candidate, modulus, limbCount);
        }

        void SubtractModulusFromCandidate(
            _Inout_updates_(limbCountPlusOne) ULONG* candidate,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            SIZE_T limbCountPlusOne) noexcept
        {
            UNREFERENCED_PARAMETER(limbCountPlusOne);
            ULONGLONG borrow = 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONGLONG subtrahend = static_cast<ULONGLONG>(modulus[index]) + borrow;
                const ULONGLONG minuend = candidate[index];
                candidate[index] = static_cast<ULONG>(minuend - subtrahend);
                borrow = minuend < subtrahend ? 1 : 0;
            }
            candidate[limbCount] = static_cast<ULONG>(
                static_cast<ULONGLONG>(candidate[limbCount]) - borrow);
        }

        _Must_inspect_result_
        NTSTATUS MontgomeryReduce(
            _Inout_updates_(productCount) ULONG* product,
            SIZE_T productCount,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            ULONG n0Prime,
            _Out_writes_(limbCount) ULONG* output) noexcept
        {
            if (product == nullptr ||
                productCount < (limbCount * 2) + 1 ||
                modulus == nullptr ||
                output == nullptr ||
                limbCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONG factor = static_cast<ULONG>(product[index] * n0Prime);
                ULONGLONG carry = 0;
                for (SIZE_T modulusIndex = 0; modulusIndex < limbCount; ++modulusIndex) {
                    const SIZE_T productIndex = index + modulusIndex;
                    const ULONGLONG value =
                        static_cast<ULONGLONG>(factor) *
                        static_cast<ULONGLONG>(modulus[modulusIndex]) +
                        static_cast<ULONGLONG>(product[productIndex]) +
                        carry;
                    product[productIndex] = static_cast<ULONG>(value);
                    carry = value >> 32;
                }

                SIZE_T carryIndex = index + limbCount;
                while (carry != 0 && carryIndex < productCount) {
                    const ULONGLONG value = static_cast<ULONGLONG>(product[carryIndex]) + carry;
                    product[carryIndex] = static_cast<ULONG>(value);
                    carry = value >> 32;
                    ++carryIndex;
                }
                if (carry != 0) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }

            ULONG* candidate = product + limbCount;
            if (CompareCandidateToModulus(candidate, modulus, limbCount, limbCount + 1) >= 0) {
                SubtractModulusFromCandidate(candidate, modulus, limbCount, limbCount + 1);
            }

            RtlCopyMemory(output, candidate, limbCount * sizeof(ULONG));
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS MontgomeryMultiply(
            _In_reads_(limbCount) const ULONG* left,
            _In_reads_(limbCount) const ULONG* right,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            ULONG n0Prime,
            _Out_writes_(limbCount) ULONG* output,
            _Inout_updates_(productCount) ULONG* product,
            SIZE_T productCount) noexcept
        {
            MultiplyLimbs(left, right, limbCount, product, productCount);
            return MontgomeryReduce(product, productCount, modulus, limbCount, n0Prime, output);
        }

        void ConvertToMontgomery(
            _In_reads_(limbCount) const ULONG* regular,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            _Out_writes_(limbCount) ULONG* montgomery) noexcept
        {
            RtlCopyMemory(montgomery, regular, limbCount * sizeof(ULONG));
            for (SIZE_T bit = 0; bit < limbCount * 32; ++bit) {
                LeftShiftOneModulo(montgomery, modulus, limbCount);
            }
        }

        _Must_inspect_result_
        bool ExponentBitIsSet(
            _In_reads_bytes_(exponentLength) const UCHAR* exponent,
            SIZE_T exponentLength,
            SIZE_T bitIndexFromLeastSignificant) noexcept
        {
            const SIZE_T byteIndexFromEnd = bitIndexFromLeastSignificant / 8;
            if (byteIndexFromEnd >= exponentLength) {
                return false;
            }
            const SIZE_T byteIndex = exponentLength - 1 - byteIndexFromEnd;
            const UCHAR mask = static_cast<UCHAR>(1U << (bitIndexFromLeastSignificant % 8));
            return (exponent[byteIndex] & mask) != 0;
        }

        void SelectLimbs(
            _Inout_updates_(limbCount) ULONG* destination,
            _In_reads_(limbCount) const ULONG* candidate,
            SIZE_T limbCount,
            bool useCandidate) noexcept
        {
            const ULONG mask = useCandidate ? 0xffffffffUL : 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                destination[index] = static_cast<ULONG>(
                    (destination[index] & ~mask) |
                    (candidate[index] & mask));
            }
        }

        void SwapLimbsConditional(
            _Inout_updates_(limbCount) ULONG* left,
            _Inout_updates_(limbCount) ULONG* right,
            SIZE_T limbCount,
            ULONG swap) noexcept
        {
            const ULONG mask = static_cast<ULONG>(0UL - (swap & 1UL));
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONG value = static_cast<ULONG>(mask & (left[index] ^ right[index]));
                left[index] ^= value;
                right[index] ^= value;
            }
        }

        void SetSmallLimbs(
            _Out_writes_(limbCount) ULONG* value,
            SIZE_T limbCount,
            ULONG smallValue) noexcept
        {
            RtlZeroMemory(value, limbCount * sizeof(ULONG));
            if (limbCount != 0) {
                value[0] = smallValue;
            }
        }

        void AddModulusToLimbsInPlace(
            _Inout_updates_(limbCount) ULONG* value,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount) noexcept
        {
            ULONGLONG carry = 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONGLONG sum =
                    static_cast<ULONGLONG>(value[index]) +
                    static_cast<ULONGLONG>(modulus[index]) +
                    carry;
                value[index] = static_cast<ULONG>(sum);
                carry = sum >> 32;
            }
        }

        void AddLimbsModulo(
            _In_reads_(limbCount) const ULONG* left,
            _In_reads_(limbCount) const ULONG* right,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            _Out_writes_(limbCount) ULONG* output,
            _Out_writes_(limbCountPlusOne) ULONG* candidate,
            SIZE_T limbCountPlusOne) noexcept
        {
            RtlZeroMemory(candidate, limbCountPlusOne * sizeof(ULONG));

            ULONGLONG carry = 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONGLONG sum =
                    static_cast<ULONGLONG>(left[index]) +
                    static_cast<ULONGLONG>(right[index]) +
                    carry;
                candidate[index] = static_cast<ULONG>(sum);
                carry = sum >> 32;
            }
            candidate[limbCount] = static_cast<ULONG>(carry);

            if (CompareCandidateToModulus(candidate, modulus, limbCount, limbCountPlusOne) >= 0) {
                SubtractModulusFromCandidate(candidate, modulus, limbCount, limbCountPlusOne);
            }

            RtlCopyMemory(output, candidate, limbCount * sizeof(ULONG));
        }

        void SubtractLimbsModulo(
            _In_reads_(limbCount) const ULONG* left,
            _In_reads_(limbCount) const ULONG* right,
            _In_reads_(limbCount) const ULONG* modulus,
            SIZE_T limbCount,
            _Out_writes_(limbCount) ULONG* output) noexcept
        {
            ULONGLONG borrow = 0;
            for (SIZE_T index = 0; index < limbCount; ++index) {
                const ULONGLONG subtrahend = static_cast<ULONGLONG>(right[index]) + borrow;
                const ULONGLONG minuend = left[index];
                output[index] = static_cast<ULONG>(minuend - subtrahend);
                borrow = minuend < subtrahend ? 1 : 0;
            }

            if (borrow != 0) {
                AddModulusToLimbsInPlace(output, modulus, limbCount);
            }
        }

        _Must_inspect_result_
        NTSTATUS FfdheModularExponent(
            _In_ const FfdheGroupParameters& parameters,
            _In_reads_bytes_(baseLength) const UCHAR* base,
            SIZE_T baseLength,
            _In_reads_bytes_(exponentLength) const UCHAR* exponent,
            SIZE_T exponentLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            if (base == nullptr ||
                baseLength == 0 ||
                exponent == nullptr ||
                exponentLength == 0 ||
                output == nullptr ||
                outputLength < parameters.ModulusLength) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T limbCount = LimbCountForBytes(parameters.ModulusLength);
            const SIZE_T productCount = (limbCount * 2) + 1;

            HeapArray<UCHAR> modulusBytes(parameters.ModulusLength);
            HeapArray<UCHAR> normalizedBase(parameters.ModulusLength);
            HeapArray<ULONG> modulus(limbCount);
            HeapArray<ULONG> baseRegular(limbCount);
            HeapArray<ULONG> baseMontgomery(limbCount);
            HeapArray<ULONG> result(limbCount);
            HeapArray<ULONG> scratch(limbCount);
            HeapArray<ULONG> product(productCount);
            if (!modulusBytes.IsValid() ||
                !normalizedBase.IsValid() ||
                !modulus.IsValid() ||
                !baseRegular.IsValid() ||
                !baseMontgomery.IsValid() ||
                !result.IsValid() ||
                !scratch.IsValid() ||
                !product.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = ParseHexToBytes(
                parameters.ModulusHex,
                modulusBytes.Get(),
                modulusBytes.Count());
            if (NT_SUCCESS(status)) {
                status = NormalizeFfdhePublicKey(
                    base,
                    baseLength,
                    normalizedBase.Get(),
                    normalizedBase.Count());
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            BigEndianToLimbs(modulusBytes.Get(), modulusBytes.Count(), modulus.Get(), modulus.Count());
            BigEndianToLimbs(normalizedBase.Get(), normalizedBase.Count(), baseRegular.Get(), baseRegular.Count());

            ConvertToMontgomery(baseRegular.Get(), modulus.Get(), limbCount, baseMontgomery.Get());
            RtlZeroMemory(result.Get(), result.Count() * sizeof(ULONG));
            result[0] = 1;
            ConvertToMontgomery(result.Get(), modulus.Get(), limbCount, result.Get());

            const ULONG n0Prime = MontgomeryN0Prime(modulus[0]);
            const SIZE_T exponentBits = exponentLength * 8;
            for (SIZE_T remaining = exponentBits; remaining > 0; --remaining) {
                status = MontgomeryMultiply(
                    result.Get(),
                    result.Get(),
                    modulus.Get(),
                    limbCount,
                    n0Prime,
                    scratch.Get(),
                    product.Get(),
                    product.Count());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                RtlCopyMemory(result.Get(), scratch.Get(), limbCount * sizeof(ULONG));

                const bool exponentBit = ExponentBitIsSet(exponent, exponentLength, remaining - 1);
                status = MontgomeryMultiply(
                    result.Get(),
                    baseMontgomery.Get(),
                    modulus.Get(),
                    limbCount,
                    n0Prime,
                    scratch.Get(),
                    product.Get(),
                    product.Count());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                SelectLimbs(result.Get(), scratch.Get(), limbCount, exponentBit);
            }

            RtlZeroMemory(scratch.Get(), scratch.Count() * sizeof(ULONG));
            scratch[0] = 1;
            status = MontgomeryMultiply(
                result.Get(),
                scratch.Get(),
                modulus.Get(),
                limbCount,
                n0Prime,
                result.Get(),
                product.Get(),
                product.Count());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            LimbsToBigEndian(result.Get(), result.Count(), output, parameters.ModulusLength);
            return STATUS_SUCCESS;
        }

        _Ret_notnull_
        ULONG* X448Block(_Inout_ HeapArray<ULONG>& blocks, SIZE_T index) noexcept
        {
            return blocks.Get() + (index * X448LimbCount);
        }

        _Must_inspect_result_
        NTSTATUS X448FieldMultiply(
            _In_reads_(X448LimbCount) const ULONG* left,
            _In_reads_(X448LimbCount) const ULONG* right,
            _In_reads_(X448LimbCount) const ULONG* modulus,
            ULONG n0Prime,
            _Out_writes_(X448LimbCount) ULONG* output,
            _Inout_updates_(X448ProductCount) ULONG* product) noexcept
        {
            return MontgomeryMultiply(
                left,
                right,
                modulus,
                X448LimbCount,
                n0Prime,
                output,
                product,
                X448ProductCount);
        }

        _Must_inspect_result_
        NTSTATUS X448FieldSquare(
            _In_reads_(X448LimbCount) const ULONG* value,
            _In_reads_(X448LimbCount) const ULONG* modulus,
            ULONG n0Prime,
            _Out_writes_(X448LimbCount) ULONG* output,
            _Inout_updates_(X448ProductCount) ULONG* product) noexcept
        {
            return X448FieldMultiply(value, value, modulus, n0Prime, output, product);
        }

        _Must_inspect_result_
        NTSTATUS MontgomeryExponentiatePublic(
            _In_reads_(X448LimbCount) const ULONG* baseMontgomery,
            _In_reads_bytes_(exponentLength) const UCHAR* exponent,
            SIZE_T exponentLength,
            _In_reads_(X448LimbCount) const ULONG* modulus,
            ULONG n0Prime,
            _Out_writes_(X448LimbCount) ULONG* outputMontgomery,
            _Out_writes_(X448LimbCount) ULONG* scratch,
            _Inout_updates_(X448ProductCount) ULONG* product) noexcept
        {
            if (baseMontgomery == nullptr ||
                exponent == nullptr ||
                exponentLength == 0 ||
                modulus == nullptr ||
                outputMontgomery == nullptr ||
                scratch == nullptr ||
                product == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SetSmallLimbs(outputMontgomery, X448LimbCount, 1);
            ConvertToMontgomery(outputMontgomery, modulus, X448LimbCount, outputMontgomery);

            for (SIZE_T remaining = exponentLength * 8; remaining > 0; --remaining) {
                NTSTATUS status = X448FieldSquare(
                    outputMontgomery,
                    modulus,
                    n0Prime,
                    scratch,
                    product);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                RtlCopyMemory(outputMontgomery, scratch, X448LimbCount * sizeof(ULONG));

                if (ExponentBitIsSet(exponent, exponentLength, remaining - 1)) {
                    status = X448FieldMultiply(
                        outputMontgomery,
                        baseMontgomery,
                        modulus,
                        n0Prime,
                        scratch,
                        product);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    RtlCopyMemory(outputMontgomery, scratch, X448LimbCount * sizeof(ULONG));
                }
            }

            return STATUS_SUCCESS;
        }

        void ClampX448Scalar(_Inout_updates_(KeyExchangeX448KeyLength) UCHAR* scalar) noexcept
        {
            scalar[0] &= 252;
            scalar[55] |= 128;
        }

        _Must_inspect_result_
        NTSTATUS X448(
            _In_reads_bytes_(KeyExchangeX448KeyLength) const UCHAR* privateKey,
            _In_reads_bytes_(KeyExchangeX448KeyLength) const UCHAR* peerPublicKey,
            _Out_writes_bytes_(KeyExchangeX448KeyLength) UCHAR* output) noexcept
        {
            if (privateKey == nullptr || peerPublicKey == nullptr || output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (IsAllZero(peerPublicKey, KeyExchangeX448KeyLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<UCHAR> scalar(KeyExchangeX448KeyLength);
            HeapArray<UCHAR> modulusBytes(KeyExchangeX448KeyLength);
            HeapArray<UCHAR> exponentBytes(KeyExchangeX448KeyLength);
            HeapArray<ULONG> blocks(X448LimbCount * X448FieldBlockCount);
            HeapArray<ULONG> product(X448ProductCount);
            HeapArray<ULONG> candidate(X448LimbCount + 1);
            if (!scalar.IsValid() ||
                !modulusBytes.IsValid() ||
                !exponentBytes.IsValid() ||
                !blocks.IsValid() ||
                !product.IsValid() ||
                !candidate.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = ParseHexToBytes(X448PrimeHex, modulusBytes.Get(), modulusBytes.Count());
            if (NT_SUCCESS(status)) {
                status = ParseHexToBytes(X448PrimeMinusTwoHex, exponentBytes.Get(), exponentBytes.Count());
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            RtlCopyMemory(scalar.Get(), privateKey, scalar.Count());
            ClampX448Scalar(scalar.Get());

            ULONG* modulus = X448Block(blocks, 0);
            ULONG* x1 = X448Block(blocks, 1);
            ULONG* x2 = X448Block(blocks, 2);
            ULONG* z2 = X448Block(blocks, 3);
            ULONG* x3 = X448Block(blocks, 4);
            ULONG* z3 = X448Block(blocks, 5);
            ULONG* a = X448Block(blocks, 6);
            ULONG* aa = X448Block(blocks, 7);
            ULONG* b = X448Block(blocks, 8);
            ULONG* bb = X448Block(blocks, 9);
            ULONG* e = X448Block(blocks, 10);
            ULONG* c = X448Block(blocks, 11);
            ULONG* d = X448Block(blocks, 12);
            ULONG* da = X448Block(blocks, 13);
            ULONG* cb = X448Block(blocks, 14);
            ULONG* temp1 = X448Block(blocks, 15);
            ULONG* temp2 = X448Block(blocks, 16);
            ULONG* oneMontgomery = X448Block(blocks, 17);
            ULONG* a24Montgomery = X448Block(blocks, 18);
            ULONG* oneRegular = X448Block(blocks, 19);
            ULONG* inverse = X448Block(blocks, 20);
            ULONG* resultMontgomery = X448Block(blocks, 21);
            ULONG* resultRegular = X448Block(blocks, 22);

            BigEndianToLimbs(modulusBytes.Get(), modulusBytes.Count(), modulus, X448LimbCount);
            LittleEndianToLimbs(peerPublicKey, KeyExchangeX448KeyLength, x1, X448LimbCount);
            if (CompareLimbs(x1, modulus, X448LimbCount) >= 0) {
                SubtractLimbsInPlace(x1, modulus, X448LimbCount);
            }

            ConvertToMontgomery(x1, modulus, X448LimbCount, x1);

            SetSmallLimbs(oneRegular, X448LimbCount, 1);
            RtlCopyMemory(oneMontgomery, oneRegular, X448LimbCount * sizeof(ULONG));
            ConvertToMontgomery(oneMontgomery, modulus, X448LimbCount, oneMontgomery);

            SetSmallLimbs(a24Montgomery, X448LimbCount, X448A24);
            ConvertToMontgomery(a24Montgomery, modulus, X448LimbCount, a24Montgomery);

            RtlCopyMemory(x2, oneMontgomery, X448LimbCount * sizeof(ULONG));
            RtlZeroMemory(z2, X448LimbCount * sizeof(ULONG));
            RtlCopyMemory(x3, x1, X448LimbCount * sizeof(ULONG));
            RtlCopyMemory(z3, oneMontgomery, X448LimbCount * sizeof(ULONG));

            const ULONG n0Prime = MontgomeryN0Prime(modulus[0]);
            ULONG swap = 0;
            for (int bit = 447; bit >= 0; --bit) {
                const ULONG scalarBit = static_cast<ULONG>((scalar[bit >> 3] >> (bit & 7)) & 1);
                swap ^= scalarBit;
                SwapLimbsConditional(x2, x3, X448LimbCount, swap);
                SwapLimbsConditional(z2, z3, X448LimbCount, swap);
                swap = scalarBit;

                AddLimbsModulo(x2, z2, modulus, X448LimbCount, a, candidate.Get(), candidate.Count());
                status = X448FieldSquare(a, modulus, n0Prime, aa, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SubtractLimbsModulo(x2, z2, modulus, X448LimbCount, b);
                status = X448FieldSquare(b, modulus, n0Prime, bb, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SubtractLimbsModulo(aa, bb, modulus, X448LimbCount, e);
                AddLimbsModulo(x3, z3, modulus, X448LimbCount, c, candidate.Get(), candidate.Count());
                SubtractLimbsModulo(x3, z3, modulus, X448LimbCount, d);

                status = X448FieldMultiply(d, a, modulus, n0Prime, da, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = X448FieldMultiply(c, b, modulus, n0Prime, cb, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                AddLimbsModulo(da, cb, modulus, X448LimbCount, temp1, candidate.Get(), candidate.Count());
                status = X448FieldSquare(temp1, modulus, n0Prime, x3, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SubtractLimbsModulo(da, cb, modulus, X448LimbCount, temp1);
                status = X448FieldSquare(temp1, modulus, n0Prime, temp2, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = X448FieldMultiply(x1, temp2, modulus, n0Prime, z3, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = X448FieldMultiply(aa, bb, modulus, n0Prime, x2, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = X448FieldMultiply(a24Montgomery, e, modulus, n0Prime, temp1, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                AddLimbsModulo(aa, temp1, modulus, X448LimbCount, temp2, candidate.Get(), candidate.Count());
                status = X448FieldMultiply(e, temp2, modulus, n0Prime, z2, product.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            SwapLimbsConditional(x2, x3, X448LimbCount, swap);
            SwapLimbsConditional(z2, z3, X448LimbCount, swap);

            status = MontgomeryExponentiatePublic(
                z2,
                exponentBytes.Get(),
                exponentBytes.Count(),
                modulus,
                n0Prime,
                inverse,
                temp1,
                product.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = X448FieldMultiply(x2, inverse, modulus, n0Prime, resultMontgomery, product.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = X448FieldMultiply(
                resultMontgomery,
                oneRegular,
                modulus,
                n0Prime,
                resultRegular,
                product.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            LimbsToLittleEndian(resultRegular, X448LimbCount, output, KeyExchangeX448KeyLength);
            RtlSecureZeroMemory(scalar.Get(), scalar.Count());
            RtlSecureZeroMemory(blocks.Get(), blocks.Count() * sizeof(ULONG));
            RtlSecureZeroMemory(product.Get(), product.Count() * sizeof(ULONG));
            RtlSecureZeroMemory(candidate.Get(), candidate.Count() * sizeof(ULONG));
            return STATUS_SUCCESS;
        }
    }

    void KeyExchangeKeyPair::Reset() noexcept
    {
        RtlSecureZeroMemory(PrivateKey, sizeof(PrivateKey));
        PrivateKeyLength = 0;
        RtlSecureZeroMemory(PublicKey, sizeof(PublicKey));
        PublicKeyLength = 0;
        CngPrivateKey.Close();
        Group = KeyExchangeGroup::Secp256r1;
    }

    bool KeyExchange::IsSupportedGroup(KeyExchangeGroup group) noexcept
    {
        switch (group) {
        case KeyExchangeGroup::Secp256r1:
        case KeyExchangeGroup::Secp384r1:
        case KeyExchangeGroup::Secp521r1:
        case KeyExchangeGroup::X25519:
        case KeyExchangeGroup::X448:
        case KeyExchangeGroup::Ffdhe2048:
        case KeyExchangeGroup::Ffdhe3072:
        case KeyExchangeGroup::Ffdhe4096:
        case KeyExchangeGroup::Ffdhe6144:
        case KeyExchangeGroup::Ffdhe8192:
            return true;
        default:
            return false;
        }
    }

    bool KeyExchange::IsRawKeyShareGroup(KeyExchangeGroup group) noexcept
    {
        return group == KeyExchangeGroup::X25519 || group == KeyExchangeGroup::X448;
    }

    SIZE_T KeyExchange::PublicKeyLength(KeyExchangeGroup group) noexcept
    {
        switch (group) {
        case KeyExchangeGroup::X25519:
            return KeyExchangeX25519KeyLength;
        case KeyExchangeGroup::X448:
            return KeyExchangeX448KeyLength;
        case KeyExchangeGroup::Secp256r1:
            return 65;
        case KeyExchangeGroup::Secp384r1:
            return 97;
        case KeyExchangeGroup::Secp521r1:
            return 133;
        case KeyExchangeGroup::Ffdhe2048:
            return KeyExchangeFfdhe2048Length;
        case KeyExchangeGroup::Ffdhe3072:
            return KeyExchangeFfdhe3072Length;
        case KeyExchangeGroup::Ffdhe4096:
            return KeyExchangeFfdhe4096Length;
        case KeyExchangeGroup::Ffdhe6144:
            return KeyExchangeFfdhe6144Length;
        case KeyExchangeGroup::Ffdhe8192:
            return KeyExchangeFfdhe8192Length;
        default:
            return 0;
        }
    }

    SIZE_T KeyExchange::SharedSecretLength(KeyExchangeGroup group) noexcept
    {
        switch (group) {
        case KeyExchangeGroup::X25519:
            return KeyExchangeX25519KeyLength;
        case KeyExchangeGroup::X448:
            return KeyExchangeX448KeyLength;
        case KeyExchangeGroup::Secp256r1:
            return 32;
        case KeyExchangeGroup::Secp384r1:
            return 48;
        case KeyExchangeGroup::Secp521r1:
            return 66;
        case KeyExchangeGroup::Ffdhe2048:
            return KeyExchangeFfdhe2048Length;
        case KeyExchangeGroup::Ffdhe3072:
            return KeyExchangeFfdhe3072Length;
        case KeyExchangeGroup::Ffdhe4096:
            return KeyExchangeFfdhe4096Length;
        case KeyExchangeGroup::Ffdhe6144:
            return KeyExchangeFfdhe6144Length;
        case KeyExchangeGroup::Ffdhe8192:
            return KeyExchangeFfdhe8192Length;
        default:
            return 0;
        }
    }

    NTSTATUS KeyExchange::GenerateKeyPair(
        const CngProviderCache* cache,
        KeyExchangeGroup group,
        KeyExchangeKeyPair& keyPair) noexcept
    {
        keyPair.Reset();
        keyPair.Group = group;

        if (group == KeyExchangeGroup::X25519 || group == KeyExchangeGroup::X448) {
            const SIZE_T keyLength = group == KeyExchangeGroup::X25519 ?
                KeyExchangeX25519KeyLength :
                KeyExchangeX448KeyLength;
            NTSTATUS status = CngProvider::GenerateRandom(keyPair.PrivateKey, keyLength);
            if (!NT_SUCCESS(status)) {
                keyPair.Reset();
                return status;
            }

            if (group == KeyExchangeGroup::X25519) {
                ClampX25519Scalar(keyPair.PrivateKey);
            }
            else {
                ClampX448Scalar(keyPair.PrivateKey);
            }
            keyPair.PrivateKeyLength = keyLength;
            status = DerivePublicKey(
                group,
                keyPair.PrivateKey,
                keyPair.PrivateKeyLength,
                keyPair.PublicKey,
                sizeof(keyPair.PublicKey),
                &keyPair.PublicKeyLength);
            if (!NT_SUCCESS(status)) {
                keyPair.Reset();
            }
            return status;
        }

        const FfdheGroupParameters* ffdhe = FindFfdheGroup(group);
        if (ffdhe != nullptr) {
            NTSTATUS status = CngProvider::GenerateRandom(
                keyPair.PrivateKey,
                ffdhe->PrivateExponentLength);
            if (!NT_SUCCESS(status)) {
                keyPair.Reset();
                return status;
            }

            keyPair.PrivateKey[0] = static_cast<UCHAR>(keyPair.PrivateKey[0] | 0x80);
            keyPair.PrivateKeyLength = ffdhe->PrivateExponentLength;
            status = DerivePublicKey(
                group,
                keyPair.PrivateKey,
                keyPair.PrivateKeyLength,
                keyPair.PublicKey,
                sizeof(keyPair.PublicKey),
                &keyPair.PublicKeyLength);
            if (!NT_SUCCESS(status)) {
                keyPair.Reset();
            }
            return status;
        }

        NTSTATUS status = STATUS_SUCCESS;
        const EcCurve curve = ToEcCurve(group, &status);
        if (!NT_SUCCESS(status)) {
            keyPair.Reset();
            return status;
        }

        status = CngProvider::GenerateEcdhKeyPair(cache, curve, keyPair.CngPrivateKey);
        if (NT_SUCCESS(status)) {
            status = ExportNistPublicKey(
                keyPair.CngPrivateKey,
                keyPair.PublicKey,
                sizeof(keyPair.PublicKey),
                &keyPair.PublicKeyLength);
        }
        if (!NT_SUCCESS(status)) {
            keyPair.Reset();
        }
        return status;
    }

    NTSTATUS KeyExchange::DerivePublicKey(
        KeyExchangeGroup group,
        const UCHAR* privateKey,
        SIZE_T privateKeyLength,
        UCHAR* publicKey,
        SIZE_T publicKeyCapacity,
        SIZE_T* publicKeyLength) noexcept
    {
        if (publicKeyLength != nullptr) {
            *publicKeyLength = 0;
        }

        const FfdheGroupParameters* ffdhe = FindFfdheGroup(group);
        if (ffdhe != nullptr) {
            if (privateKey == nullptr ||
                privateKeyLength == 0 ||
                publicKey == nullptr ||
                publicKeyCapacity < ffdhe->ModulusLength ||
                publicKeyLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = FfdheModularExponent(
                *ffdhe,
                FfdheGeneratorTwo,
                sizeof(FfdheGeneratorTwo),
                privateKey,
                privateKeyLength,
                publicKey,
                publicKeyCapacity);
            if (NT_SUCCESS(status)) {
                *publicKeyLength = ffdhe->ModulusLength;
            }
            return status;
        }

        if (group == KeyExchangeGroup::X25519) {
            if (privateKey == nullptr ||
                privateKeyLength != KeyExchangeX25519KeyLength ||
                publicKey == nullptr ||
                publicKeyCapacity < KeyExchangeX25519KeyLength ||
                publicKeyLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = X25519(privateKey, X25519BasePoint, publicKey);
            if (NT_SUCCESS(status)) {
                *publicKeyLength = KeyExchangeX25519KeyLength;
            }
            return status;
        }

        if (group == KeyExchangeGroup::X448) {
            if (privateKey == nullptr ||
                privateKeyLength != KeyExchangeX448KeyLength ||
                publicKey == nullptr ||
                publicKeyCapacity < KeyExchangeX448KeyLength ||
                publicKeyLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = X448(privateKey, X448BasePoint, publicKey);
            if (NT_SUCCESS(status)) {
                *publicKeyLength = KeyExchangeX448KeyLength;
            }
            return status;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KeyExchange::DeriveSharedSecret(
        KeyExchangeGroup group,
        const UCHAR* privateKey,
        SIZE_T privateKeyLength,
        const UCHAR* peerPublicKey,
        SIZE_T peerPublicKeyLength,
        UCHAR* sharedSecret,
        SIZE_T sharedSecretCapacity,
        SIZE_T* sharedSecretLength) noexcept
    {
        const FfdheGroupParameters* ffdhe = FindFfdheGroup(group);
        if (ffdhe != nullptr) {
            if (sharedSecretLength != nullptr) {
                *sharedSecretLength = 0;
            }
            if (privateKey == nullptr ||
                privateKeyLength == 0 ||
                peerPublicKey == nullptr ||
                peerPublicKeyLength == 0 ||
                sharedSecret == nullptr ||
                sharedSecretCapacity < ffdhe->ModulusLength ||
                sharedSecretLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = ValidateFfdhePublicKeyWithParameters(*ffdhe, peerPublicKey, peerPublicKeyLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = FfdheModularExponent(
                *ffdhe,
                peerPublicKey,
                peerPublicKeyLength,
                privateKey,
                privateKeyLength,
                sharedSecret,
                sharedSecretCapacity);
            if (NT_SUCCESS(status)) {
                *sharedSecretLength = ffdhe->ModulusLength;
            }
            return status;
        }

        if (group != KeyExchangeGroup::X25519 && group != KeyExchangeGroup::X448) {
            if (sharedSecretLength != nullptr) {
                *sharedSecretLength = 0;
            }
            return STATUS_NOT_SUPPORTED;
        }

        const SIZE_T keyLength = group == KeyExchangeGroup::X25519 ?
            KeyExchangeX25519KeyLength :
            KeyExchangeX448KeyLength;

        if (group == KeyExchangeGroup::X25519) {
            NTSTATUS status = ValidateX25519Lengths(
                privateKey,
                privateKeyLength,
                peerPublicKey,
                peerPublicKeyLength,
                sharedSecret,
                sharedSecretCapacity,
                sharedSecretLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else {
            if (sharedSecretLength != nullptr) {
                *sharedSecretLength = 0;
            }
            if (privateKey == nullptr ||
                privateKeyLength != keyLength ||
                peerPublicKey == nullptr ||
                peerPublicKeyLength != keyLength ||
                sharedSecret == nullptr ||
                sharedSecretCapacity < keyLength ||
                sharedSecretLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        NTSTATUS status = group == KeyExchangeGroup::X25519 ?
            X25519(privateKey, peerPublicKey, sharedSecret) :
            X448(privateKey, peerPublicKey, sharedSecret);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (IsAllZero(sharedSecret, keyLength)) {
            RtlSecureZeroMemory(sharedSecret, sharedSecretCapacity);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        *sharedSecretLength = keyLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS KeyExchange::DeriveSharedSecret(
        const CngProviderCache* cache,
        const KeyExchangeKeyPair& keyPair,
        const UCHAR* peerPublicKey,
        SIZE_T peerPublicKeyLength,
        UCHAR* sharedSecret,
        SIZE_T sharedSecretCapacity,
        SIZE_T* sharedSecretLength) noexcept
    {
        if (sharedSecretLength != nullptr) {
            *sharedSecretLength = 0;
        }

        if (!IsValidBuffer(peerPublicKey, peerPublicKeyLength) ||
            sharedSecret == nullptr ||
            sharedSecretLength == nullptr ||
            sharedSecretCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (keyPair.Group == KeyExchangeGroup::X25519 ||
            keyPair.Group == KeyExchangeGroup::X448 ||
            IsFfdheGroup(keyPair.Group)) {
            return DeriveSharedSecret(
                keyPair.Group,
                keyPair.PrivateKey,
                keyPair.PrivateKeyLength,
                peerPublicKey,
                peerPublicKeyLength,
                sharedSecret,
                sharedSecretCapacity,
                sharedSecretLength);
        }

        NTSTATUS status = STATUS_SUCCESS;
        const EcCurve curve = ToEcCurve(keyPair.Group, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapObject<CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = CngProvider::ImportEcdhPublicKey(
            cache,
            curve,
            peerPublicKey,
            peerPublicKeyLength,
            *peerKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return CngProvider::DeriveEcdhSecret(
            cache,
            keyPair.CngPrivateKey,
            *peerKey.Get(),
            sharedSecret,
            sharedSecretCapacity,
            sharedSecretLength);
    }

    NTSTATUS KeyExchange::ValidateFiniteFieldPublicKey(
        KeyExchangeGroup group,
        const UCHAR* publicKey,
        SIZE_T publicKeyLength) noexcept
    {
        const FfdheGroupParameters* ffdhe = FindFfdheGroup(group);
        if (ffdhe == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        if (publicKey == nullptr || publicKeyLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return ValidateFfdhePublicKeyWithParameters(*ffdhe, publicKey, publicKeyLength);
    }

    NTSTATUS KeyExchange::FindFiniteFieldGroup(
        const UCHAR* prime,
        SIZE_T primeLength,
        const UCHAR* generator,
        SIZE_T generatorLength,
        KeyExchangeGroup* group) noexcept
    {
        if (group != nullptr) {
            *group = KeyExchangeGroup::Ffdhe2048;
        }
        if (prime == nullptr ||
            primeLength == 0 ||
            generator == nullptr ||
            generatorLength == 0 ||
            group == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sizeof(FfdheGroups) / sizeof(FfdheGroups[0]); ++index) {
            const FfdheGroupParameters& parameters = FfdheGroups[index];
            HeapArray<UCHAR> modulus(parameters.ModulusLength);
            HeapArray<UCHAR> normalizedPrime(parameters.ModulusLength);
            HeapArray<UCHAR> normalizedGenerator(parameters.ModulusLength);
            if (!modulus.IsValid() || !normalizedPrime.IsValid() || !normalizedGenerator.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = ParseHexToBytes(parameters.ModulusHex, modulus.Get(), modulus.Count());
            if (NT_SUCCESS(status)) {
                status = NormalizeFfdhePublicKey(
                    prime,
                    primeLength,
                    normalizedPrime.Get(),
                    normalizedPrime.Count());
            }
            if (NT_SUCCESS(status)) {
                status = NormalizeFfdhePublicKey(
                    generator,
                    generatorLength,
                    normalizedGenerator.Get(),
                    normalizedGenerator.Count());
            }
            if (status == STATUS_INVALID_NETWORK_RESPONSE) {
                continue;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (CompareBigEndian(modulus.Get(), normalizedPrime.Get(), modulus.Count()) == 0 &&
                normalizedGenerator[normalizedGenerator.Count() - 1] == 2) {
                bool generatorIsTwo = true;
                for (SIZE_T byteIndex = 0; byteIndex + 1 < normalizedGenerator.Count(); ++byteIndex) {
                    if (normalizedGenerator[byteIndex] != 0) {
                        generatorIsTwo = false;
                        break;
                    }
                }
                if (generatorIsTwo) {
                    *group = parameters.Group;
                    return STATUS_SUCCESS;
                }
            }
        }

        return STATUS_NOT_SUPPORTED;
    }
}
}
