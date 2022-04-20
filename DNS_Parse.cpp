#include <string>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <algorithm>

using namespace std;

// Defines every error thrown during DNS name validation
enum dnsNameError { VALID, INVALID_NAME_ERROR, NUMERIC_NAME_ERROR, INVALID_CHAR_ERROR };

// DNS Flag section of the header split into bit fields
struct DNSFlags {
    unsigned char QR : 1;
    unsigned char OPCODE : 4;
    unsigned char AA : 1;
    unsigned char TC : 1;
    unsigned char RD : 1;
    unsigned char RA : 1;
    unsigned char Z : 3;
    unsigned char RCODE : 4;
};

// Defines data stored by all question records
struct DNSQuestion {
    string qName;
    unsigned int qType;
    unsigned int qClass;
};

// Defines data stored by all resource records
struct ResourceRecord {
    string rName;
    unsigned int rType;
    unsigned int rClass;
    signed int rTtl;
    unsigned int rdLength;    
    string rData;
};

// Stores all DNS Message data and allows printing of the data
class DNSMessage {
    public:
        DNSMessage();
        DNSMessage(string hexData);
        
        void printData();
        
    private:
        unsigned int dnsID;
        DNSFlags headerFlags;
        unsigned int qdCount;
        unsigned int anCount;
        unsigned int nsCount;
        unsigned int arCount;

        vector<DNSQuestion> questions;
        vector<ResourceRecord> answers;
        vector<ResourceRecord> authority;
        vector<ResourceRecord> additional;

        void parseHeader(string& hexData, int& begin);
        void parseQuestions(string& hexData, int& begin);
        void parseResourceRecords(string& hexData, int& begin);

        string printableHeader();
        string printableQuestions();
        string printableResourceRecords();

        void parseRRData(string& hexData, int& begin, ResourceRecord& dataRecord);
        string extractName(string& hexData, int& begin);
        dnsNameError validateName(string dnsName);
};

DNSMessage::DNSMessage() {
    this->dnsID = 0;
    this->headerFlags = {};
    this->qdCount = 0;
    this->anCount = 0;
    this->nsCount = 0;
    this->arCount = 0;
}

// Creates DNSMessage object from hex formatted string
DNSMessage::DNSMessage(string hexData) {
    int nextSection = 0;
    this->parseHeader(hexData, nextSection);
    this->parseQuestions(hexData, nextSection);
    this->parseResourceRecords(hexData, nextSection);
}

// Prints DNS Object's data in proper format
void DNSMessage::printData() {
    string output = string();
    output.append(this->printableHeader());
    output.append("\n" + this->printableQuestions());
    output.append("\n" + this->printableResourceRecords());
    
    cout << output;
}

// Returns a string of header data in a readable format
string DNSMessage::printableHeader() {
    // This can be refactored to read types from a different source (e.g. a file)
    unordered_map<int, string> opcodeMap = {
        {0, "QUERY"}, {1, "IQUERY"}, {2, "STATUS"}, {3, "UNASSIGNED"},
        {4, "NOTIFY"}, {5, "UPDATE"}, {6, "DSO"} };
    unordered_map<int, string> rcodeMap = {
        {0, "NOERROR"}, {1,"FORMERR"}, {2,"SERVFAIL"}, {3,"NXDOMAIN"},
        {4,"NOTIMP"}, {5,"REFUSED"}, {6,"YXDOMAIN"}, {7,"YXRRSET"},
        {8,"NXRRSET"}, {9,"NOTAUTH"}, {10,"NOTAUTH"}, {11,"NOTAUTH"},
        {12,"UNASSIGNED"}, {13,"UNASSIGNED"}, {14,"UNASSIGNED"}, {15,"UNASSIGNED"},
        {16,"BADVERS/BADSIG"}, {17,"BADKEY"}, {18,"BADTIME"}, {19,"BADMODE"},
        {20,"BADNAME"}, {21,"BADALG"}, {22,"BADTRUNC"}, {23,"BADCOOKIE"}, 
        {65535, "RESERVED"} };
        
    for(int i = 7; i <= 15; i++) {
        opcodeMap[i] = "UNASSIGNED";
    }
    for(int i = 24; i <= 3840; i++) {
        rcodeMap[i] = "UNASSIGNED";
    }
    for(int i = 3841; i <= 4095; i++) {
        rcodeMap[i] = "RESERVED";
    }
    for(int i = 4096; i <= 65534; i++) {
        rcodeMap[i] = "UNASSIGNED";
    }
    
    string output = ";; ->>HEADER<<- ";
    output.append("opcode: " + opcodeMap[this->headerFlags.OPCODE] + ", ");
    output.append("status: " + rcodeMap[this->headerFlags.RCODE] + ", ");
    output.append("id: " + to_string(this->dnsID) + "\n");

    output.append(";; flags:");
    if(this->headerFlags.QR) {
        output.append(" qr");
    }
    if(this->headerFlags.AA) {
        output.append(" aa");
    }
    if(this->headerFlags.TC) {
        output.append(" tc");
    }
    if(this->headerFlags.RD) {
        output.append(" rd");
    }
    if(this->headerFlags.RA) {
        output.append(" ra");
    }
    output.append("; QUERY: " + to_string(this->qdCount) + ", ");
    output.append("ANSWER: " + to_string(this->anCount) + ", ");
    output.append("AUTHORITY: " + to_string(this->nsCount) + ", ");
    output.append("ADDITIONAL: " + to_string(this->arCount) + "\n");
    return output;
}

// Returns a string of question data in a readable format
string DNSMessage::printableQuestions() {
    // This can be refactored to read types from a different source (e.g. a file)
    unordered_map<int, string> qTypes = {
        {0, "RESERVED"}, {1, "A"}, {2, "NS"}, {3, "MD"},
        {4, "MF"}, {5, "CNAME"}, {6, "SOA"}, {7, "MB"},
        {8, "MG"}, {9, "MR"}, {10, "NULL"}, {11, "WKS"},
        {12, "PTR"}, {13, "HINFO"}, {14, "MINFO"}, {15, "MX"},
        {16, "TXT"}, {17, "RP"}, {18, "AFSDB"}, {19, "X25"},
        {20, "ISDN"}, {21, "RT"}, {22, "NSAP"}, {23, "NSAP-PTR"},
        {24, "SIG"}, {25, "KEY"}, {26, "PX"}, {27, "GPOS"},
        {28, "AAAA"}, {29, "LOC"}, {30, "NXT"}, {31, "EID"},
        {32, "NIMLOC"}, {33, "SRV"}, {34, "ATMA"}, {35, "NAPTR"},
        {36, "KX"}, {37, "CERT"}, {38, "A6"}, {39, "DNAME"},
        {40, "SINK"}, {41, "OPT"}, {42, "APL"}, {43, "DS"},
        {44, "SSHFP"}, {45, "IPSECKEY"}, {46, "RRSIG"}, {47, "NSEC"},
        {48, "DNSKEY"}, {49, "DHCID"}, {50, "NSEC3"}, {51, "NSEC3PARAM"},
        {52, "TLSA"}, {53, "SMIMEA"}, {54, "UNASSIGNED"}, {55, "HIP"},
        {56, "NINFO"}, {57, "RKEY"}, {58, "TALINK"}, {59, "CDS"},
        {60, "CDNSKEY"}, {61, "OPENGPKEY"}, {62, "CSYNC"}, {63, "ZONEMD"},
        {64, "SVCB"}, {65, "HTTPS"}, {99, "SPF"}, {100, "UINFO"},
        {101, "UID"}, {102, "GID"}, {103, "UNSPEC"}, {104, "NID"},
        {105, "L32"}, {106, "L64"}, {107, "LP"}, {108, "EUI48"},
        {109, "EUI64"}, {249, "TKEY"}, {250, "TSIG"}, {251, "IXFR"},
        {252, "AXFR"}, {253, "MAILB"}, {254, "MAILA"}, {255, "*"},
        {256, "URI"}, {257, "CAA"}, {258, "AVC"}, {259, "DOA"},
        {260, "AMTRELAY"}, {32768, "TA"}, {32769, "DLV"}, {65535, "RESERVED"},
    };
    unordered_map<int, string> classMap = {
        {0, "RESERVED"}, {1, "IN"}, {2, "UNASSIGNED"}, {3, "CH"},
        {4, "HS"}, {254, "NONE"}, {255, "ANY"} };
    
    for(int i = 5; i <= 253; i++) {
        classMap[i] = "UNASSIGNED";
    }
    for(int i = 256; i <= 65279; i++) {
        classMap[i] = "UNASSIGNED";
    }
    for(int i = 65280; i <= 65535; i++) {
        classMap[i] = "RESERVED";
    }
    for(int i = 66; i <= 98; i++) {
        qTypes[i] = "UNASSIGNED";
    }
    for(int i = 110; i <= 248; i++) {
        qTypes[i] = "UNASSIGNED";
    }
    for(int i = 261; i <= 32767; i++) {
        qTypes[i] = "UNASSIGNED";
    }
    for(int i = 32770; i <= 65279; i++) {
        qTypes[i] = "UNASSIGNED";
    }
    for(int i = 65280; i <= 65534; i++) {
        qTypes[i] = "PRIVATE";
    }
    
    string output = string();
    if(qdCount) {
        output = ";; QUESTION SECTION:\n";
        for(int i = 0; i < this->questions.size(); i++) {
            output.append(";" + this->questions[i].qName + "\t\t");
            output.append(classMap[this->questions[i].qClass] + "\t");
            output.append(qTypes[this->questions[i].qType] + "\n");
        }
    }

    return output;
}

// Returns a string of data from all resource records in a readable format
string DNSMessage::printableResourceRecords() {
    // This can be refactored to read types from a different source (e.g. a file)
    unordered_map<int, string> rrTypes = {
        {0, "RESERVED"}, {1, "A"}, {2, "NS"}, {3, "MD"},
        {4, "MF"}, {5, "CNAME"}, {6, "SOA"}, {7, "MB"},
        {8, "MG"}, {9, "MR"}, {10, "NULL"}, {11, "WKS"},
        {12, "PTR"}, {13, "HINFO"}, {14, "MINFO"}, {15, "MX"},
        {16, "TXT"}, {17, "RP"}, {18, "AFSDB"}, {19, "X25"},
        {20, "ISDN"}, {21, "RT"}, {22, "NSAP"}, {23, "NSAP-PTR"},
        {24, "SIG"}, {25, "KEY"}, {26, "PX"}, {27, "GPOS"},
        {28, "AAAA"}, {29, "LOC"}, {30, "NXT"}, {31, "EID"},
        {32, "NIMLOC"}, {33, "SRV"}, {34, "ATMA"}, {35, "NAPTR"},
        {36, "KX"}, {37, "CERT"}, {38, "A6"}, {39, "DNAME"},
        {40, "SINK"}, {41, "OPT"}, {42, "APL"}, {43, "DS"},
        {44, "SSHFP"}, {45, "IPSECKEY"}, {46, "RRSIG"}, {47, "NSEC"},
        {48, "DNSKEY"}, {49, "DHCID"}, {50, "NSEC3"}, {51, "NSEC3PARAM"},
        {52, "TLSA"}, {53, "SMIMEA"}, {54, "UNASSIGNED"}, {55, "HIP"},
        {56, "NINFO"}, {57, "RKEY"}, {58, "TALINK"}, {59, "CDS"},
        {60, "CDNSKEY"}, {61, "OPENGPKEY"}, {62, "CSYNC"}, {63, "ZONEMD"},
        {64, "SVCB"}, {65, "HTTPS"}, {99, "SPF"}, {100, "UINFO"},
        {101, "UID"}, {102, "GID"}, {103, "UNSPEC"}, {104, "NID"},
        {105, "L32"}, {106, "L64"}, {107, "LP"}, {108, "EUI48"},
        {109, "EUI64"}, {249, "TKEY"}, {250, "TSIG"}, {251, "IXFR"},
        {252, "AXFR"}, {253, "MAILB"}, {254, "MAILA"}, {255, "*"},
        {256, "URI"}, {257, "CAA"}, {258, "AVC"}, {259, "DOA"},
        {260, "AMTRELAY"}, {32768, "TA"}, {32769, "DLV"}, {65535, "RESERVED"},
    };
    unordered_map<int, string> classMap = {
        {0, "RESERVED"}, {1, "IN"}, {2, "UNASSIGNED"}, {3, "CH"},
        {4, "HS"}, {254, "NONE"}, {255, "ANY"} };
    
    for(int i = 5; i <= 253; i++) {
        classMap[i] = "UNASSIGNED";
    }
    for(int i = 256; i <= 65279; i++) {
        classMap[i] = "UNASSIGNED";
    }
    for(int i = 65280; i <= 65535; i++) {
        classMap[i] = "RESERVED";
    }
    for(int i = 66; i <= 98; i++) {
        rrTypes[i] = "UNASSIGNED";
    }
    for(int i = 110; i <= 248; i++) {
        rrTypes[i] = "UNASSIGNED";
    }
    for(int i = 261; i <= 32767; i++) {
        rrTypes[i] = "UNASSIGNED";
    }
    for(int i = 32770; i <= 65279; i++) {
        rrTypes[i] = "UNASSIGNED";
    }
    for(int i = 65280; i <= 65534; i++) {
        rrTypes[i] = "PRIVATE";
    }
    
    string output = string();
    
    if(anCount) {
        output.append(";; ANSWER SECTION:\n");
        for(int i = 0; i < this->answers.size(); i++) {
            output.append(this->answers[i].rName + "\t\t");
            output.append(to_string(this->answers[i].rTtl) + "\t");
            output.append(classMap[this->answers[i].rClass] + "\t");
            output.append(rrTypes[this->answers[i].rType] + "\t");
            output.append(this->answers[i].rData + "\n");
        }
    }
    if(nsCount) {
        output.append(";; AUTHORITY SECTION:\n");
        for(int i = 0; i < this->authority.size(); i++) {
            output.append(this->authority[i].rName + "\t\t");
            output.append(to_string(this->authority[i].rTtl) + "\t");
            output.append(classMap[this->authority[i].rClass] + "\t");
            output.append(rrTypes[this->authority[i].rType] + "\t");
            output.append(this->authority[i].rData + "\n");
        }
    }
    if(arCount) {
        output.append(";; ADDITIONAL SECTION:\n");
        for(int i = 0; i < this->additional.size(); i++) {
            output.append(this->additional[i].rName + "\t\t");
            output.append(to_string(this->additional[i].rTtl) + "\t");
            output.append(classMap[this->additional[i].rClass] + "\t");
            output.append(rrTypes[this->additional[i].rType] + "\t");
            output.append(this->additional[i].rData + "\n");
        }
    }
    return output;
}

// Parses the constant length header of DNS message data
void DNSMessage::parseHeader(string& hexData, int& begin) {
    // Alternatively, could shift first then mask
    // Would make mask values simpler
    const int qrMask = 0x8000;
    const int opMask = 0x7800;
    const int aaMask = 0x0400;
    const int tcMask = 0x0200;
    const int rdMask = 0x0100;
    const int raMask = 0x0080;
    const int zMask  = 0x0070;
    const int rcMask = 0x000F;
    
    const int qrShift = 15;
    const int opShift = 11;
    const int aaShift = 10;
    const int tcShift = 9;
    const int rdShift = 8;
    const int raShift = 7;
    const int zShift  = 4;
    const int rcShift = 0;
    
    // Header is first 12 bytes of hexData - two hex chars = 1 byte
    this->dnsID = stoul(hexData.substr(0, 4), nullptr, 16);

    unsigned int flags = stoul(hexData.substr(4,4), nullptr, 16);
    
    this->headerFlags.QR = (flags & (qrMask)) >> qrShift; 
    this->headerFlags.OPCODE = (flags & (opMask)) >> opShift; 
    this->headerFlags.AA = (flags & (aaMask)) >> aaShift; 
    this->headerFlags.TC = (flags & (tcMask)) >> tcShift; 
    this->headerFlags.RD = (flags & (rdMask)) >> rdShift; 
    this->headerFlags.RA = (flags & (raMask)) >> raShift; 
    this->headerFlags.Z  = (flags & (zMask))  >> zShift;
    this->headerFlags.RCODE = (flags & (rcMask)) >> rcShift; 
    
    this->qdCount = stoul(hexData.substr(8,4), nullptr, 16);
    this->anCount = stoul(hexData.substr(12,4), nullptr, 16);
    this->nsCount = stoul(hexData.substr(16,4), nullptr, 16);
    this->arCount = stoul(hexData.substr(20,4), nullptr, 16);
    
    begin = 24;
    
    return;
}

// Parses all question records and updates location to point to the next byte
void DNSMessage::parseQuestions(string& hexData, int& begin) {   
    if(begin < 0) {
        return;
    }
    
    for(int i = 0; i < this->qdCount; i++) {
        DNSQuestion newQuery = {};
        string name = this->extractName(hexData, begin);
        int nameError = this->validateName(name);
        
        if(nameError == VALID) {
            newQuery.qName = name;
        }
        else {
            // Invalid name - stop parsing completely
            newQuery.qName = "INVALID NAME ERROR: " + to_string(nameError);
            newQuery.qType = 0;
            newQuery.qClass = 0;
            this->questions.push_back(newQuery);
            begin = -1;
            return;
        }
        
        if(begin + 8 < hexData.length()) {
            newQuery.qType = stoul(hexData.substr(begin, 4), nullptr, 16);
            newQuery.qClass = stoul(hexData.substr(begin + 4, 4), nullptr, 16);
            this->questions.push_back(newQuery);
            begin += 8;
        }
        else {
            // Invalid size - stop parsing completely
            newQuery.qName = "INVALID DATA SIZE";
            newQuery.qType = 0;
            newQuery.qClass = 0;
            this->questions.push_back(newQuery);
            begin = -1;
            return;
        }
        
    }
    
    return;
}

// Parses all resource records and updates location to point to the next byte
void DNSMessage::parseResourceRecords(string& hexData, int& begin) {
    vector<unsigned int> recordCounts = {this->anCount, this->nsCount, this->arCount};
    
    if(begin < 0) {
        return;
    }
    
    for(int count = 0; count < 3; count++) {
        for(int i = 0; i < recordCounts[count]; i++) {
            ResourceRecord newRecord = {};
            string name = this->extractName(hexData, begin);
            int nameError = this->validateName(name);

            if (nameError == VALID) {
                newRecord.rName = name;
            }
            else {
                // Invalid name - stop parsing completely
                newRecord.rName = "INVALID NAME ERROR: " + to_string(nameError);
                newRecord.rType = 0;
                newRecord.rClass = 0;
                newRecord.rTtl = 0;
                newRecord.rdLength = 0;
                newRecord.rData = string();
                switch(count) {
                    case 0:
                        this->answers.push_back(newRecord);
                        break;
                    case 1:
                        this->authority.push_back(newRecord);
                        break;
                    case 2:
                        this->additional.push_back(newRecord);
                        break;
                }
                begin = -1;
                return;
            }
            
            if(begin + 20 < hexData.length()) {
                newRecord.rType = stoul(hexData.substr(begin, 4), nullptr, 16);
                newRecord.rClass = stoul(hexData.substr(begin + 4, 4), nullptr, 16);
                newRecord.rTtl = stoi(hexData.substr(begin + 8, 8), nullptr, 16);
                newRecord.rdLength = stoul(hexData.substr(begin + 16, 4), nullptr, 16);
                begin += 20;
                
                this->parseRRData(hexData, begin, newRecord);
                switch(count) {
                    case 0:
                        this->answers.push_back(newRecord);
                        break;
                    case 1:
                        this->authority.push_back(newRecord);
                        break;
                    case 2:
                        this->additional.push_back(newRecord);
                        break;
                }
            }
            else {
                // Invalid size - stop parsing completely
                newRecord.rName = "INVALID DATA SIZE";
                newRecord.rType = 0;
                newRecord.rClass = 0;
                newRecord.rTtl = 0;
                newRecord.rdLength = 0;
                newRecord.rData = string();
                switch(count) {
                    case 0:
                        this->answers.push_back(newRecord);
                        break;
                    case 1:
                        this->authority.push_back(newRecord);
                        break;
                    case 2:
                        this->additional.push_back(newRecord);
                        break;
                }
                begin = -1;
                return;
            }
            
        }
    }
    
    return;
}

// Parses the RDATA field of a resource record, depending on the type
// Only supports types "A","CNAME","TXT","AAAA" - can be extended to support other types
void DNSMessage::parseRRData(string& hexData, int& begin, ResourceRecord& dataRecord) {
    // Only allow supported types
    unordered_map<int, string> supportedRTypes = {{1, "A"}, {5, "CNAME"}, {16, "TXT"}, {28, "AAAA"}};
    
    if(supportedRTypes.find(dataRecord.rType) == supportedRTypes.end()) {
        dataRecord.rData = "NOT SUPPORTED";
        begin += dataRecord.rdLength;
        return;
    }
    
    if(dataRecord.rType == 1) {
        // Read data as IPv4 address
        if(begin + (dataRecord.rdLength*2 - 1) < hexData.length()) {
            for(int i = 0; i < (dataRecord.rdLength*2); i+=2, begin+=2) {
                unsigned int octet = stoul(hexData.substr(begin, 2), nullptr, 16);
                dataRecord.rData += to_string(octet);
                if(i + 2 < dataRecord.rdLength*2) {
                    dataRecord.rData += ".";
                }
            }
        }
        else {
            dataRecord.rData = "INVALID DATA SIZE";
            begin = -1;
        }
    }
    else if(dataRecord.rType == 5) {
        // Read data as a record name
        dataRecord.rData = this->extractName(hexData, begin);
    }
    else if(dataRecord.rType == 16) {
        // Read data as ASCII text
        if(begin + (dataRecord.rdLength*2 - 1) < hexData.length()) {
            for(int i = 0; i < (dataRecord.rdLength*2); i+=2, begin+=2) {
                char dataChar = stoul(hexData.substr(begin, 2), nullptr, 16);
                dataRecord.rData += dataChar;
            }
        }
        else {
            dataRecord.rData = "INVALID DATA SIZE";
            begin = -1;
        }
    }
    else if(dataRecord.rType == 28) {
        // Read data as IPv6 Address
        if(begin + (dataRecord.rdLength*2 - 1) < hexData.length()) {
            vector<string> ipSections;
            for(int i = 0; i < (dataRecord.rdLength*2); i+=4, begin+=4) {
                string section = hexData.substr(begin, 4);
                transform(section.begin(), section.end(), section.begin(), ::tolower);
                ipSections.push_back(section);
            }
            
            // Clear leading 0's from each IPv6 subsection
            for(int i = 0; i < ipSections.size(); i++) {
                for(int j = 0; j < 3; j++) {
                    if(ipSections[i][0] == '0') {
                        ipSections[i].erase(0, 1);
                    }
                }
            }

            int maxStart = -1;
            int maxEnd = -1;
            int curStart = -1;
            int curEnd = -1;
            
            // Find longest section of repeating zeroes
            for(int i = 0; i < ipSections.size(); i++) {
                if(ipSections[i] == "0") {
                    if(curStart == -1) {
                        curStart = i;
                    }
                    else {
                        curEnd = i;
                    }
                    if(curEnd > 0 && (curEnd - curStart > maxEnd - maxStart)) {
                        maxStart = curStart;
                        maxEnd = curEnd;
                    }
                }
                else {
                    curStart = -1;
                    curEnd = -1;
                }
            }
            
            // Combine IPv6 subsections into one string
            for(int i = 0; i < ipSections.size(); i++) {
                // Truncate longest consecutive zero section
                if(i >= maxStart && i <= maxEnd) {
                    if(i == maxEnd) {
                        dataRecord.rData += ":";
                    }
                    if(maxEnd == ipSections.size()) {
                        dataRecord.rData += ":";
                    }
                }
                else {
                    if(i >= 1) {
                        dataRecord.rData += ":";
                    }
                    dataRecord.rData.append(ipSections[i]);
                }
            }
        }
        else {
            dataRecord.rData = "INVALID DATA SIZE";
            begin = -1;
        }
    }
    
    return;
}

// Extracts the ASCII name from hex data and updates location to point to the next byte
string DNSMessage::extractName(string& hexData, int& begin) {
    //Max length is 255 octets, including beginning label and trailing dot
    const int maxNameLength = 253;
    string name = string();
    unsigned int labelLength;
    int offset = begin / 2;
    
    if((begin + 1) < hexData.length()) {
        // Support for name compression - check for first two bits being 1, followed by byte offset
        if(hexData[begin] == 'C' || hexData[begin] == 'D' || hexData[begin] == 'E' || hexData[begin] == 'F') {
            if((begin + 3) < hexData.length()) {
                unsigned int offsetMask = 0x3FFF;
                int nameLoc = stoul(hexData.substr(begin, 4), nullptr, 16) & offsetMask;
                nameLoc *= 2;
                
                // Recursively extract name value from new location
                name.append(this->extractName(hexData, nameLoc));
                
                begin += 4;
                labelLength = 0;
            }
            else {
                return string();
            }
        }
        else {
            labelLength = stoul(hexData.substr(begin,2), nullptr, 16);
            begin+= 2;
        }
    }
    else {
        return string();
    }
    
    while(labelLength) {
        for(int i = 0; i < labelLength*2; i+=2, begin+=2) {
            // Convert hex to unsigned long, then convert that to ASCII character
            if((begin + 1) < hexData.length()) {
                char labelChar = stoul(hexData.substr(begin, 2), nullptr, 16);
                name += labelChar;
            } 
            else {
                return string();
            }
            // Prevents reading unnecessary data if the name is invalid
            if(name.length() > maxNameLength) {
                return string();
            }
        }
        
        name += '.';
        if((begin + 1) < hexData.length()) {
            if(hexData[begin] == 'C' || hexData[begin] == 'D' || hexData[begin] == 'E' || hexData[begin] == 'F') {
                if((begin + 3) < hexData.length()) {
                    unsigned int offsetMask = 0x3FFF;
                    int nameLoc = stoul(hexData.substr(begin, 4), nullptr, 16) & offsetMask;
                    nameLoc *= 2;
                    
                    // Recursively extract name value from new location
                    name.append(this->extractName(hexData, nameLoc));

                    begin += 4;
                    labelLength = 0;
                }
                else {
                    return string();
                }
            }
            else {
                labelLength = stoul(hexData.substr(begin,2), nullptr, 16);
                begin+= 2;
            }
        }
        else {
            return string();
        }
    }

    return name;
}

// Returns a code defined in the dnsNameError enum after validating the name passed in
dnsNameError DNSMessage::validateName(string dnsName) {  
    const int maxNameLength = 254;
    const int minNameLength = 3;
    const int maxLabelLength = 63;
    
    int currLabelLength = 0;
    int nameLength = 0;
    bool prevCharDot = true;
    bool onlyNumbers = true;

    if(dnsName.length() < minNameLength || dnsName.length() > maxNameLength) {
        return INVALID_NAME_ERROR;
    }

    for(int i = 0; i < dnsName.length(); i++) {
        char currChar = toupper(dnsName[i]);
        
        switch(currChar) {
            case '-':
            case 'A' ... 'Z':
                onlyNumbers = false;
                [[fallthrough]];
            case '0' ... '9':
                prevCharDot = false;
                if(++currLabelLength > maxLabelLength) {
                    return INVALID_NAME_ERROR;
                }
                break;
            case '.':
                // Error: either started with a dot or has 2+ in a row
                if (prevCharDot) {
                    return INVALID_NAME_ERROR;
                }
                else {
                    prevCharDot = true;
                    currLabelLength = 0;
                }
                break;
            default:
                // Any other character in DNS name is unsupported
                return INVALID_CHAR_ERROR;
                break;
        }
    }
    
    // DNS name cannot consist of only numbers
    return onlyNumbers ? NUMERIC_NAME_ERROR : VALID;
}


// Cleans formatted hex data of other characters into a usable format
string extractRawHex(string hexString) {
    // Minimum of 12 bytes to have complete header data
    const int minLength = 24;
    vector<char> removeChar = {' ', '"', '\\', 'x'};

    // Clean input of standard characters for proper parsing
    for(int i = 0; i < removeChar.size(); i++) {
        hexString.erase(remove(hexString.begin(), hexString.end(), removeChar[i]), hexString.end());
    }
    
    // Convert string to upper case for consistency
    transform(hexString.begin(), hexString.end(), hexString.begin(), ::toupper);
    
    if(hexString.length() < minLength) {
        // Error: DNS Message has incomplete header data - return empty string
        return string();
    }
    return hexString;
}

int main() {
    string rawDns;
    string hexDns;
    string line;
    
    cout << "Please enter hex encoded DNS string. Type 'exit' to complete input:" << endl;

    while(getline(cin, line)) {
        line.erase(remove(line.begin(), line.end(), '\n'), line.end());
        if(line == "exit") {
            break;
        }

        rawDns.append(line);
    }
    
    if((hexDns = extractRawHex(rawDns)).length() < 1) {
        cout << "Error: Invalid hex encoded string. Aborting." << endl;
    }
    else {
        DNSMessage decodedData(hexDns);
        decodedData.printData();
    }
    
    return 0;
}