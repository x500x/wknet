import java.io.ByteArrayOutputStream;

import javax.xml.namespace.QName;

import com.siemens.ct.exi.core.CodingMode;
import com.siemens.ct.exi.core.EXIBodyEncoder;
import com.siemens.ct.exi.core.EXIFactory;
import com.siemens.ct.exi.core.EncodingOptions;
import com.siemens.ct.exi.core.FidelityOptions;
import com.siemens.ct.exi.core.helpers.DefaultEXIFactory;
import com.siemens.ct.exi.core.values.StringValue;
import com.siemens.ct.exi.core.values.QNameValue;
import com.siemens.ct.exi.core.values.Value;
import com.siemens.ct.exi.core.values.BooleanValue;
import com.siemens.ct.exi.core.values.IntegerValue;
import com.siemens.ct.exi.core.values.DecimalValue;
import com.siemens.ct.exi.core.values.FloatValue;
import com.siemens.ct.exi.core.values.DateTimeValue;
import com.siemens.ct.exi.core.values.BinaryBase64Value;
import com.siemens.ct.exi.core.values.BinaryHexValue;
import com.siemens.ct.exi.core.types.DateTimeType;
import com.siemens.ct.exi.grammars.GrammarFactory;

public final class GenerateExiFixtures {
    private static byte[] encode(CodingMode mode, boolean includeOptions, boolean includeCookie) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        if (includeOptions) {
            encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        }
        if (includeCookie) {
            encodingOptions.setOption(EncodingOptions.INCLUDE_COOKIE);
        }
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeCharacters(new StringValue("text"));
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeRepeatedElements(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        if (mode != CodingMode.BIT_PACKED) {
            EncodingOptions encodingOptions = EncodingOptions.createDefault();
            encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
            factory.setEncodingOptions(encodingOptions);
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeStartElement("", "item", null);
        body.encodeCharacters(new StringValue("a"));
        body.encodeEndElement();
        body.encodeStartElement("", "item", null);
        body.encodeCharacters(new StringValue("b"));
        body.encodeEndElement();
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeNamespaceDocument(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_PREFIX, true);

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("urn:test", "root", "p");
        body.encodeNamespaceDeclaration("urn:test", "p");
        body.encodeAttribute("urn:test", "a", "p", new StringValue("x"));
        body.encodeCharacters(new StringValue("text"));
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeNamespaceDocumentWithoutPrefixes() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("urn:test", "root", null);
        body.encodeAttribute("urn:test", "a", null, new StringValue("x"));
        body.encodeCharacters(new StringValue("text"));
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static EXIBodyEncoder createBodyEncoder(
            EXIFactory factory,
            ByteArrayOutputStream output,
            boolean includeOptions) throws Exception {
        if (includeOptions) {
            EncodingOptions encodingOptions = EncodingOptions.createDefault();
            encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
            factory.setEncodingOptions(encodingOptions);
        }
        return factory.createEXIStreamEncoder().encodeHeader(output);
    }

    private static void encodeTextElement(
            EXIBodyEncoder body,
            String localName,
            String value) throws Exception {
        body.encodeStartElement("", localName, null);
        body.encodeCharacters(new StringValue(value));
        body.encodeEndElement();
    }

    private static byte[] encodeLocalAndGlobalValueHits() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, false);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        encodeTextElement(body, "a", "same");
        encodeTextElement(body, "a", "same");
        encodeTextElement(body, "b", "same");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeBoundedValuePartitions() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);
        factory.setValuePartitionCapacity(2);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        encodeTextElement(body, "a", "one");
        encodeTextElement(body, "b", "two");
        encodeTextElement(body, "c", "three");
        encodeTextElement(body, "a", "one");
        encodeTextElement(body, "a", "one");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeValueMaxLength() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);
        factory.setValueMaxLength(1);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        encodeTextElement(body, "a", "long");
        encodeTextElement(body, "a", "long");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeFragment() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);
        factory.setFragment(true);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        encodeTextElement(body, "a", "one");
        encodeTextElement(body, "b", "two");
        encodeTextElement(body, "a", "three");
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeSmallBlocks(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.setBlockSize(1);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        encodeTextElement(body, "a", "one");
        encodeTextElement(body, "b", "two");
        encodeTextElement(body, "a", "three");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeFidelityEvents(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_DTD, true);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_COMMENT, true);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_PI, true);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeDocType("root", "", "urn:sys", "<!ENTITY ent \"value\">");
        body.encodeComment("before".toCharArray(), 0, 6);
        body.encodeProcessingInstruction("pre", "data");
        body.encodeStartElement("", "root", null);
        body.encodeComment("inside".toCharArray(), 0, 6);
        body.encodeProcessingInstruction("inner", "value");
        body.encodeEntityReference("ent");
        body.encodeEndElement();
        body.encodeComment("after".toCharArray(), 0, 5);
        body.encodeProcessingInstruction("post", "done");
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeLargeAndSmallChannels() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.COMPRESSION);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeStartElement("", "large", null);
        for (int index = 0; index < 101; ++index) {
            body.encodeCharacters(new StringValue("x"));
        }
        body.encodeEndElement();
        body.encodeStartElement("", "small", null);
        body.encodeCharacters(new StringValue("y"));
        body.encodeEndElement();
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeXsiType(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_PREFIX, true);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema", "xsd");
        body.encodeAttributeXsiType(
                new QNameValue("http://www.w3.org/2001/XMLSchema", "string", "xsd"),
                "xsi");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeSelfContained(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_SC, true);
        factory.setSelfContainedElements(new QName[] { new QName("", "item") });

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = createBodyEncoder(factory, output, true);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        encodeTextElement(body, "item", "one");
        encodeTextElement(body, "item", "two");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeTypedValue(
            CodingMode mode,
            String xsdType,
            Value value) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_PREFIX, true);
        factory.setGrammars(GrammarFactory.newInstance().createXSDTypesOnlyGrammars());

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        encodingOptions.setOption(EncodingOptions.INCLUDE_SCHEMA_ID);
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema", "xsd");
        body.encodeAttributeXsiType(
                new QNameValue("http://www.w3.org/2001/XMLSchema", xsdType, "xsd"),
                "xsi");
        body.encodeCharacters(value);
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeXsiNil(CodingMode mode) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(mode);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_PREFIX, true);
        factory.setGrammars(GrammarFactory.newInstance().createXSDTypesOnlyGrammars());

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        encodingOptions.setOption(EncodingOptions.INCLUDE_SCHEMA_ID);
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        body.encodeAttributeXsiNil(BooleanValue.BOOLEAN_VALUE_TRUE, "xsi");
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeSchemaLessSchemaIdNil() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        encodingOptions.setOption(EncodingOptions.INCLUDE_SCHEMA_ID);
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeCharacters(new StringValue("text"));
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeSchemaLessDatatypeRepresentationMap() throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);
        factory.setDatatypeRepresentationMap(
                new QName[] { new QName("http://www.w3.org/2001/XMLSchema", "decimal") },
                new QName[] { new QName("http://www.w3.org/2009/exi", "string") });

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeCharacters(new StringValue("12.340"));
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static byte[] encodeLexicalValue(String xsdType, String lexicalValue) throws Exception {
        EXIFactory factory = DefaultEXIFactory.newInstance();
        factory.setCodingMode(CodingMode.BIT_PACKED);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_PREFIX, true);
        factory.getFidelityOptions().setFidelity(FidelityOptions.FEATURE_LEXICAL_VALUE, true);
        factory.setGrammars(GrammarFactory.newInstance().createXSDTypesOnlyGrammars());

        EncodingOptions encodingOptions = EncodingOptions.createDefault();
        encodingOptions.setOption(EncodingOptions.INCLUDE_OPTIONS);
        encodingOptions.setOption(EncodingOptions.INCLUDE_SCHEMA_ID);
        factory.setEncodingOptions(encodingOptions);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        EXIBodyEncoder body = factory.createEXIStreamEncoder().encodeHeader(output);
        body.encodeStartDocument();
        body.encodeStartElement("", "root", null);
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        body.encodeNamespaceDeclaration("http://www.w3.org/2001/XMLSchema", "xsd");
        body.encodeAttributeXsiType(
                new QNameValue("http://www.w3.org/2001/XMLSchema", xsdType, "xsd"),
                "xsi");
        body.encodeCharacters(new StringValue(lexicalValue));
        body.encodeEndElement();
        body.encodeEndDocument();
        body.flush();
        return output.toByteArray();
    }

    private static void print(String name, byte[] bytes) {
        System.out.print(name + " = {");
        for (int index = 0; index < bytes.length; ++index) {
            if (index != 0) {
                System.out.print(", ");
            }
            System.out.printf("0x%02x", bytes[index] & 0xff);
        }
        System.out.println("};");
    }

    public static void main(String[] args) throws Exception {
        print("bit_packed", encode(CodingMode.BIT_PACKED, false, false));
        print("bit_packed_cookie", encode(CodingMode.BIT_PACKED, false, true));
        print("bit_packed_options", encode(CodingMode.BIT_PACKED, true, false));
        print("byte_packed_options", encode(CodingMode.BYTE_PACKED, true, false));
        print("pre_compression_options", encode(CodingMode.PRE_COMPRESSION, true, false));
        print("compression_options", encode(CodingMode.COMPRESSION, true, false));
        print("repeated_bit_packed", encodeRepeatedElements(CodingMode.BIT_PACKED));
        print("repeated_byte_packed", encodeRepeatedElements(CodingMode.BYTE_PACKED));
        print("namespace_prefixes", encodeNamespaceDocument(CodingMode.BIT_PACKED));
        print("namespace_prefixes_pre_compression", encodeNamespaceDocument(CodingMode.PRE_COMPRESSION));
        print("namespace_prefixes_compression", encodeNamespaceDocument(CodingMode.COMPRESSION));
        print("namespace_synthesized", encodeNamespaceDocumentWithoutPrefixes());
        print("local_global_value_hits", encodeLocalAndGlobalValueHits());
        print("bounded_value_partitions", encodeBoundedValuePartitions());
        print("value_max_length", encodeValueMaxLength());
        print("fragment", encodeFragment());
        print("small_blocks_pre_compression", encodeSmallBlocks(CodingMode.PRE_COMPRESSION));
        print("small_blocks_compression", encodeSmallBlocks(CodingMode.COMPRESSION));
        print("fidelity_bit_packed", encodeFidelityEvents(CodingMode.BIT_PACKED));
        print("fidelity_pre_compression", encodeFidelityEvents(CodingMode.PRE_COMPRESSION));
        print("large_and_small_channels", encodeLargeAndSmallChannels());
        print("xsi_type_bit_packed", encodeXsiType(CodingMode.BIT_PACKED));
        print("xsi_type_pre_compression", encodeXsiType(CodingMode.PRE_COMPRESSION));
        print("self_contained_bit_packed", encodeSelfContained(CodingMode.BIT_PACKED));
        print("self_contained_byte_packed", encodeSelfContained(CodingMode.BYTE_PACKED));
        print("typed_boolean", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "boolean",
                BooleanValue.BOOLEAN_VALUE_TRUE));
        print("typed_boolean_byte_packed", encodeTypedValue(
                CodingMode.BYTE_PACKED,
                "boolean",
                BooleanValue.BOOLEAN_VALUE_TRUE));
        print("typed_boolean_pre_compression", encodeTypedValue(
                CodingMode.PRE_COMPRESSION,
                "boolean",
                BooleanValue.BOOLEAN_VALUE_TRUE));
        print("typed_boolean_compression", encodeTypedValue(
                CodingMode.COMPRESSION,
                "boolean",
                BooleanValue.BOOLEAN_VALUE_TRUE));
        print("xsi_nil_bit_packed", encodeXsiNil(CodingMode.BIT_PACKED));
        print("xsi_nil_byte_packed", encodeXsiNil(CodingMode.BYTE_PACKED));
        print("xsi_nil_pre_compression", encodeXsiNil(CodingMode.PRE_COMPRESSION));
        print("xsi_nil_compression", encodeXsiNil(CodingMode.COMPRESSION));
        print("schema_less_schema_id_nil", encodeSchemaLessSchemaIdNil());
        print("schema_less_drmap", encodeSchemaLessDatatypeRepresentationMap());
        print("lexical_boolean", encodeLexicalValue("boolean", "1"));
        print("lexical_decimal", encodeLexicalValue("decimal", "+001.2300"));
        print("lexical_double", encodeLexicalValue("double", "-INF"));
        print("lexical_date_time", encodeLexicalValue("dateTime", "2024-05-06T07:08:09Z"));
        print("lexical_integer", encodeLexicalValue("integer", "+00042"));
        print("lexical_base64", encodeLexicalValue("base64Binary", "AAEC/w=="));
        print("lexical_hex", encodeLexicalValue("hexBinary", "00ff"));
        print("typed_integer", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "integer",
                IntegerValue.valueOf(-42)));
        print("typed_decimal", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "decimal",
                DecimalValue.parse("-12.34")));
        print("typed_float", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "float",
                new FloatValue(123, -2)));
        print("typed_base64", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "base64Binary",
                new BinaryBase64Value(new byte[] { 0, 1, 2, (byte) 0xff })));
        print("typed_hex", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "hexBinary",
                new BinaryHexValue(new byte[] { 0, 1, 2, (byte) 0xff })));
        print("typed_string", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "string",
                new StringValue("hello")));
        print("typed_int", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "int",
                IntegerValue.valueOf(-42)));
        print("typed_unsigned_int", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "unsignedInt",
                IntegerValue.valueOf(42)));
        print("typed_byte", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "byte",
                IntegerValue.valueOf(-42)));
        print("typed_non_negative_integer", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "nonNegativeInteger",
                IntegerValue.valueOf(42)));
        print("typed_date_time", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "dateTime",
                DateTimeValue.parse("2024-05-06T07:08:09.123Z", DateTimeType.dateTime)));
        print("typed_date", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "date",
                DateTimeValue.parse("2024-05-06Z", DateTimeType.date)));
        print("typed_time", encodeTypedValue(
                CodingMode.BIT_PACKED,
                "time",
                DateTimeValue.parse("07:08:09Z", DateTimeType.time)));
    }
}
