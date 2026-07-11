import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;

import org.apache.commons.compress.java.util.jar.Pack200;
import org.apache.commons.compress.harmony.pack200.Archive;
import org.apache.commons.compress.harmony.pack200.PackingOptions;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.Label;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

public final class GeneratePack200Fixtures {
    private static class RawAttribute extends Attribute {
        private final byte[] contents;

        RawAttribute(String name, byte[] contents) {
            super(name);
            this.contents = contents;
        }

        @Override
        protected ByteVector write(
                ClassWriter classWriter,
                byte[] code,
                int codeLength,
                int maxStack,
                int maxLocals) {
            ByteVector output = new ByteVector(contents.length);
            output.putByteArray(contents, 0, contents.length);
            return output;
        }
    }

    private static final class RawCodeAttribute extends RawAttribute {
        RawCodeAttribute(String name, byte[] contents) {
            super(name, contents);
        }

        @Override
        public boolean isCodeAttribute() {
            return true;
        }
    }

    private static final class ReferenceAttribute extends Attribute {
        ReferenceAttribute() {
            super("ReferenceCustom");
        }

        private static void putU2(ByteVector output, int value) {
            output.putShort(value);
        }

        @Override
        protected ByteVector write(
                ClassWriter classWriter,
                byte[] code,
                int codeLength,
                int maxStack,
                int maxLocals) {
            ByteVector output = new ByteVector(32);
            putU2(output, classWriter.newConst(Integer.valueOf(0x12345678)));
            putU2(output, classWriter.newConst(Long.valueOf(0x1122334455667788L)));
            putU2(output, classWriter.newConst(Float.valueOf(1.5f)));
            putU2(output, classWriter.newConst(Double.valueOf(2.5d)));
            putU2(output, classWriter.newConst("pack-string"));
            putU2(output, classWriter.newConst(Type.getType("Ljava/lang/String;")));
            putU2(output, classWriter.newClass("java/lang/String"));
            putU2(output, classWriter.newUTF8("Ljava/lang/String;"));
            putU2(output, classWriter.newNameType("length", "()I"));
            putU2(output, classWriter.newField("java/lang/System", "out", "Ljava/io/PrintStream;"));
            putU2(output, classWriter.newMethod("java/lang/String", "length", "()I", false));
            putU2(output, classWriter.newMethod("java/util/List", "size", "()I", true));
            putU2(output, classWriter.newUTF8("pack-utf8"));
            putU2(output, 0);
            putU2(output, classWriter.newUTF8("any-utf8"));
            putU2(output, classWriter.newField("java/lang/System", "out", "Ljava/io/PrintStream;"));
            return output;
        }
    }

    private static final class FieldReferenceAttribute extends Attribute {
        FieldReferenceAttribute() {
            super("FieldCustom");
        }

        @Override
        protected ByteVector write(
                ClassWriter classWriter,
                byte[] code,
                int codeLength,
                int maxStack,
                int maxLocals) {
            ByteVector output = new ByteVector(4);
            output.putShort(classWriter.newConst(Integer.valueOf(7)));
            output.putShort(classWriter.newUTF8("field-utf8"));
            return output;
        }
    }

    private static final class Utf8Attribute extends Attribute {
        private final String value;

        Utf8Attribute(String name, String value) {
            super(name);
            this.value = value;
        }

        @Override
        protected ByteVector write(
                ClassWriter classWriter,
                byte[] code,
                int codeLength,
                int maxStack,
                int maxLocals) {
            ByteVector output = new ByteVector(2);
            output.putShort(classWriter.newUTF8(value));
            return output;
        }
    }

    private static byte[] createJar() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            byte[] content = "hello pack200".getBytes("UTF-8");
            JarEntry entry = new JarEntry("data/hello.txt");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(content);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(content.length);
            entry.setCompressedSize(content.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(content);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] pack(byte[] jarBytes) throws Exception {
        return pack(jarBytes, -1);
    }

    private static byte[] pack(byte[] jarBytes, long segmentLimit) throws Exception {
        PackingOptions options = new PackingOptions();
        options.setGzip(false);
        options.setModificationTime(Pack200.Packer.KEEP);
        options.setDeflateHint(Pack200.Packer.KEEP);
        if (segmentLimit >= 0) {
            options.setSegmentLimit(segmentLimit);
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarInputStream jar = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
            new Archive(jar, output, options).pack();
        }
        return output.toByteArray();
    }

    private static byte[] createMultiSegmentJar() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            for (int index = 0; index < 3; ++index) {
                byte[] content = ("segment-" + index).getBytes("UTF-8");
                JarEntry entry = new JarEntry("data/segment-" + index + ".txt");
                entry.setTime(315532800000L + index * 2000L);
                CRC32 crc = new CRC32();
                crc.update(content);
                entry.setMethod(ZipEntry.STORED);
                entry.setSize(content.length);
                entry.setCompressedSize(content.length);
                entry.setCrc(crc.getValue());
                jar.putNextEntry(entry);
                jar.write(content);
                jar.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static byte[] createClassOnlyJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
                "sample/Marker",
                null,
                "java/lang/Object",
                null);
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Marker.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createCustomAttributeJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/CustomAttributes",
                null,
                "java/lang/Object",
                null);
        for (int index = 0; index < 60; ++index) {
            classWriter.visitAttribute(new RawAttribute(
                    String.format("Overflow%02d", index),
                    new byte[] { (byte) index }));
        }
        classWriter.visitAttribute(new RawAttribute(
                "PackCustom",
                new byte[] { 0x00, 0x01, 0x01, 0x07, 0x00, 0x00 }));
        classWriter.visitAttribute(new ReferenceAttribute());
        classWriter.visitField(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "value",
                "I",
                null,
                Integer.valueOf(7)).visitAttribute(new FieldReferenceAttribute());
        MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run",
                "()V",
                null,
                null);
        method.visitAttribute(new Utf8Attribute("MethodCustom", "method-utf8"));
        method.visitCode();
        method.visitInsn(Opcodes.NOP);
        method.visitInsn(Opcodes.RETURN);
        method.visitAttribute(new RawCodeAttribute(
                "CodeCustom",
                new byte[] {
                    0x00, 0x00, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x01,
                    0x00, 0x01, (byte) 0xff, (byte) 0xff }));
        method.visitMaxs(0, 0);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/CustomAttributes.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createVersionedJar(int classVersion, String className) throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                classVersion,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/" + className,
                null,
                "java/lang/Object",
                null);
        classWriter.visitSource(className + ".java", null);
        if (classVersion == Opcodes.V1_7) {
            String owner = "sample/" + className;
            MethodVisitor bootstrap = classWriter.visitMethod(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                    "bootstrap",
                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                    null,
                    null);
            bootstrap.visitCode();
            bootstrap.visitInsn(Opcodes.ACONST_NULL);
            bootstrap.visitInsn(Opcodes.ARETURN);
            bootstrap.visitMaxs(1, 3);
            bootstrap.visitEnd();
            MethodVisitor run = classWriter.visitMethod(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "run",
                    "()Ljava/lang/String;",
                    null,
                    null);
            run.visitCode();
            run.visitInvokeDynamicInsn(
                    "run",
                    "()Ljava/lang/String;",
                    new Handle(
                            Opcodes.H_INVOKESTATIC,
                            owner,
                            "bootstrap",
                            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                            false));
            run.visitInsn(Opcodes.ARETURN);
            run.visitMaxs(1, 0);
            run.visitEnd();
        }
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/" + className + ".class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createInnerClassJar() throws Exception {
        ClassWriter outerWriter = new ClassWriter(0);
        outerWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Outer",
                null,
                "java/lang/Object",
                null);
        outerWriter.visitInnerClass(
                "sample/Outer$Inner",
                "sample/Outer",
                "Inner",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        outerWriter.visitEnd();

        ClassWriter innerWriter = new ClassWriter(0);
        innerWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Outer$Inner",
                null,
                "java/lang/Object",
                null);
        innerWriter.visitInnerClass(
                "sample/Outer$Inner",
                "sample/Outer",
                "Inner",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        innerWriter.visitEnd();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            byte[][] classes = { outerWriter.toByteArray(), innerWriter.toByteArray() };
            String[] names = { "sample/Outer.class", "sample/Outer$Inner.class" };
            for (int index = 0; index < classes.length; ++index) {
                JarEntry entry = new JarEntry(names[index]);
                entry.setTime(315532800000L);
                CRC32 crc = new CRC32();
                crc.update(classes[index]);
                entry.setMethod(ZipEntry.STORED);
                entry.setSize(classes[index].length);
                entry.setCompressedSize(classes[index].length);
                entry.setCrc(crc.getValue());
                jar.putNextEntry(entry);
                jar.write(classes[index]);
                jar.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static byte[] createAbstractMethodJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
                "sample/Contract",
                null,
                "java/lang/Object",
                null);
        classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "convert",
                "(I)Ljava/lang/String;",
                null,
                null).visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Contract.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createMemberOnlyJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_SUPER,
                "sample/Model",
                null,
                "java/lang/Object",
                new String[] { "java/io/Serializable" });
        classWriter.visitField(
                Opcodes.ACC_PUBLIC,
                "value",
                "I",
                null,
                null).visitEnd();
        classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "name",
                "()Ljava/lang/String;",
                null,
                null).visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Model.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createSimpleCodeJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Answer",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "answer",
                "()I",
                null,
                null);
        method.visitCode();
        method.visitIntInsn(Opcodes.BIPUSH, 7);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Answer.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createDebugCodeJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/DebugInfo",
                "<T:Ljava/lang/Object;>Ljava/lang/Object;",
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "echo",
                "(Ljava/lang/Object;)Ljava/lang/Object;",
                "(TT;)TT;",
                null);
        Label start = new Label();
        Label end = new Label();
        method.visitCode();
        method.visitLabel(start);
        method.visitLineNumber(42, start);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ARETURN);
        method.visitLabel(end);
        method.visitLocalVariable("value", "Ljava/lang/Object;", "TT;", start, end, 0);
        method.visitMaxs(1, 1);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/DebugInfo.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createAnnotationJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Annotated",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.AnnotationVisitor annotation =
                classWriter.visitAnnotation("Lsample/Marker;", true);
        annotation.visit("value", "class");
        annotation.visitEnd();
        org.objectweb.asm.FieldVisitor field = classWriter.visitField(
                Opcodes.ACC_PUBLIC, "field", "I", null, null);
        annotation = field.visitAnnotation("Lsample/Marker;", true);
        annotation.visit("value", "field");
        annotation.visitEnd();
        field.visitEnd();
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "method",
                "(I)V",
                null,
                null);
        annotation = method.visitAnnotation("Lsample/Marker;", true);
        annotation.visit("value", "method");
        annotation.visitEnd();
        annotation = method.visitParameterAnnotation(0, "Lsample/Marker;", true);
        annotation.visit("value", "parameter");
        annotation.visitEnd();
        method.visitCode();
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 1);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Annotated.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createBranchCodeJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Branch",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "select",
                "(I)I",
                null,
                null);
        Label zero = new Label();
        method.visitCode();
        method.visitVarInsn(Opcodes.ILOAD, 0);
        method.visitJumpInsn(Opcodes.IFEQ, zero);
        method.visitInsn(Opcodes.ICONST_1);
        method.visitInsn(Opcodes.IRETURN);
        method.visitLabel(zero);
        method.visitInsn(Opcodes.ICONST_0);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Branch.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createTableSwitchJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/TableSwitch",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "map",
                "(I)I",
                null,
                null);
        Label defaultLabel = new Label();
        Label zero = new Label();
        Label one = new Label();
        Label two = new Label();
        method.visitCode();
        method.visitVarInsn(Opcodes.ILOAD, 0);
        method.visitTableSwitchInsn(0, 2, defaultLabel, zero, one, two);
        method.visitLabel(zero);
        method.visitIntInsn(Opcodes.BIPUSH, 10);
        method.visitInsn(Opcodes.IRETURN);
        method.visitLabel(one);
        method.visitIntInsn(Opcodes.BIPUSH, 20);
        method.visitInsn(Opcodes.IRETURN);
        method.visitLabel(two);
        method.visitIntInsn(Opcodes.BIPUSH, 30);
        method.visitInsn(Opcodes.IRETURN);
        method.visitLabel(defaultLabel);
        method.visitInsn(Opcodes.ICONST_M1);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/TableSwitch.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createConstructorJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Ctor",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC,
                "<init>",
                "()V",
                null,
                null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(
                Opcodes.INVOKESPECIAL,
                "java/lang/Object",
                "<init>",
                "()V",
                false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Ctor.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createExceptionHandlerJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/Catcher",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run",
                "()I",
                null,
                null);
        Label start = new Label();
        Label end = new Label();
        Label handler = new Label();
        method.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException");
        method.visitCode();
        method.visitLabel(start);
        method.visitInsn(Opcodes.ICONST_1);
        method.visitInsn(Opcodes.IRETURN);
        method.visitLabel(end);
        method.visitLabel(handler);
        method.visitInsn(Opcodes.ICONST_M1);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Catcher.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createIntegerLdcJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/IntegerLdc",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value",
                "()I",
                null,
                null);
        method.visitCode();
        method.visitLdcInsn(Integer.valueOf(100000));
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/IntegerLdc.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }


    private static byte[] createMethodReferenceJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/MethodRef",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "now",
                "()J",
                null,
                null);
        method.visitCode();
        method.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "currentTimeMillis",
                "()J",
                false);
        method.visitInsn(Opcodes.LRETURN);
        method.visitMaxs(2, 0);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/MethodRef.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createFieldReferenceJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/FieldRef",
                null,
                "java/lang/Object",
                null);
        org.objectweb.asm.MethodVisitor method = classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "max",
                "()I",
                null,
                null);
        method.visitCode();
        method.visitFieldInsn(
                Opcodes.GETSTATIC,
                "java/lang/Integer",
                "MAX_VALUE",
                "I");
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/FieldRef.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createConstantValueJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/ConstantField",
                null,
                "java/lang/Object",
                null);
        classWriter.visitField(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "VALUE",
                "I",
                null,
                Integer.valueOf(123456)).visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/ConstantField.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createDeclaredExceptionsJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_SUPER,
                "sample/Throws",
                null,
                "java/lang/Object",
                null);
        classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "run",
                "()V",
                null,
                new String[] { "java/io/IOException" }).visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Throws.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createSourceFileJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/SourceNamed",
                null,
                "java/lang/Object",
                null);
        classWriter.visitSource("Explicit.java", null);
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/SourceNamed.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] createSignatureJar() throws Exception {
        ClassWriter classWriter = new ClassWriter(0);
        classWriter.visit(
                Opcodes.V1_5,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_SUPER,
                "sample/Generic",
                "<T:Ljava/lang/Object;>Ljava/lang/Object;",
                "java/lang/Object",
                null);
        classWriter.visitField(
                Opcodes.ACC_PUBLIC,
                "value",
                "Ljava/lang/Object;",
                "TT;",
                null).visitEnd();
        classWriter.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "identity",
                "(Ljava/lang/Object;)Ljava/lang/Object;",
                "(TT;)TT;",
                null).visitEnd();
        classWriter.visitEnd();
        byte[] classBytes = classWriter.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            JarEntry entry = new JarEntry("sample/Generic.class");
            entry.setTime(315532800000L);
            CRC32 crc = new CRC32();
            crc.update(classBytes);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(classBytes.length);
            entry.setCompressedSize(classBytes.length);
            entry.setCrc(crc.getValue());
            jar.putNextEntry(entry);
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private static byte[] gzip(byte[] bytes) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(bytes);
        }
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
        if (args.length == 2 && "--custom-jar".equals(args[0])) {
            try (FileOutputStream output = new FileOutputStream(args[1])) {
                output.write(createCustomAttributeJar());
            }
            return;
        }
        if (args.length == 4 && "--versioned-jar".equals(args[0])) {
            int version = Integer.parseInt(args[1]);
            try (FileOutputStream output = new FileOutputStream(args[3])) {
                output.write(createVersionedJar(version, args[2]));
            }
            return;
        }
        byte[] jar = createJar();
        byte[] packed = pack(jar);
        byte[] multiJar = createMultiSegmentJar();
        byte[] multiPacked = pack(multiJar, 1);
        byte[] classOnlyJar = createClassOnlyJar();
        byte[] classOnlyPacked = pack(classOnlyJar);
        byte[] innerClassJar = createInnerClassJar();
        byte[] innerClassPacked = pack(innerClassJar);
        byte[] abstractMethodJar = createAbstractMethodJar();
        byte[] abstractMethodPacked = pack(abstractMethodJar);
        byte[] memberOnlyJar = createMemberOnlyJar();
        byte[] memberOnlyPacked = pack(memberOnlyJar);
        byte[] simpleCodeJar = createSimpleCodeJar();
        byte[] simpleCodePacked = pack(simpleCodeJar);
        byte[] debugCodeJar = createDebugCodeJar();
        byte[] debugCodePacked = pack(debugCodeJar);
        byte[] annotationJar = createAnnotationJar();
        byte[] annotationPacked = pack(annotationJar);
        byte[] branchCodeJar = createBranchCodeJar();
        byte[] branchCodePacked = pack(branchCodeJar);
        byte[] tableSwitchJar = createTableSwitchJar();
        byte[] tableSwitchPacked = pack(tableSwitchJar);
        byte[] constructorJar = createConstructorJar();
        byte[] constructorPacked = pack(constructorJar);
        byte[] exceptionHandlerJar = createExceptionHandlerJar();
        byte[] exceptionHandlerPacked = pack(exceptionHandlerJar);
        byte[] integerLdcJar = createIntegerLdcJar();
        byte[] integerLdcPacked = pack(integerLdcJar);
        byte[] methodReferenceJar = createMethodReferenceJar();
        byte[] methodReferencePacked = pack(methodReferenceJar);
        byte[] fieldReferenceJar = createFieldReferenceJar();
        byte[] fieldReferencePacked = pack(fieldReferenceJar);
        byte[] constantValueJar = createConstantValueJar();
        byte[] constantValuePacked = pack(constantValueJar);
        byte[] declaredExceptionsJar = createDeclaredExceptionsJar();
        byte[] declaredExceptionsPacked = pack(declaredExceptionsJar);
        byte[] sourceFileJar = createSourceFileJar();
        byte[] sourceFilePacked = pack(sourceFileJar);
        byte[] signatureJar = createSignatureJar();
        byte[] signaturePacked = pack(signatureJar);
        print("file_only_jar", jar);
        print("file_only_pack", packed);
        print("file_only_pack_gzip", gzip(packed));
        print("multi_segment_jar", multiJar);
        print("multi_segment_pack", multiPacked);
        print("multi_segment_pack_gzip", gzip(multiPacked));
        print("class_only_jar", classOnlyJar);
        print("class_only_pack", classOnlyPacked);
        print("class_only_pack_gzip", gzip(classOnlyPacked));
        print("inner_class_jar", innerClassJar);
        print("inner_class_pack", innerClassPacked);
        print("inner_class_pack_gzip", gzip(innerClassPacked));
        print("abstract_method_jar", abstractMethodJar);
        print("abstract_method_pack", abstractMethodPacked);
        print("abstract_method_pack_gzip", gzip(abstractMethodPacked));
        print("member_only_jar", memberOnlyJar);
        print("member_only_pack", memberOnlyPacked);
        print("member_only_pack_gzip", gzip(memberOnlyPacked));
        print("simple_code_jar", simpleCodeJar);
        print("simple_code_pack", simpleCodePacked);
        print("simple_code_pack_gzip", gzip(simpleCodePacked));
        print("debug_code_jar", debugCodeJar);
        print("debug_code_pack", debugCodePacked);
        print("debug_code_pack_gzip", gzip(debugCodePacked));
        print("annotation_jar", annotationJar);
        print("annotation_pack", annotationPacked);
        print("annotation_pack_gzip", gzip(annotationPacked));
        print("branch_code_jar", branchCodeJar);
        print("branch_code_pack", branchCodePacked);
        print("branch_code_pack_gzip", gzip(branchCodePacked));
        print("table_switch_jar", tableSwitchJar);
        print("table_switch_pack", tableSwitchPacked);
        print("table_switch_pack_gzip", gzip(tableSwitchPacked));
        print("constructor_jar", constructorJar);
        print("constructor_pack", constructorPacked);
        print("constructor_pack_gzip", gzip(constructorPacked));
        print("exception_handler_jar", exceptionHandlerJar);
        print("exception_handler_pack", exceptionHandlerPacked);
        print("exception_handler_pack_gzip", gzip(exceptionHandlerPacked));
        print("integer_ldc_jar", integerLdcJar);
        print("integer_ldc_pack", integerLdcPacked);
        print("integer_ldc_pack_gzip", gzip(integerLdcPacked));
        print("method_reference_jar", methodReferenceJar);
        print("method_reference_pack", methodReferencePacked);
        print("method_reference_pack_gzip", gzip(methodReferencePacked));
        print("field_reference_jar", fieldReferenceJar);
        print("field_reference_pack", fieldReferencePacked);
        print("field_reference_pack_gzip", gzip(fieldReferencePacked));
        print("constant_value_jar", constantValueJar);
        print("constant_value_pack", constantValuePacked);
        print("constant_value_pack_gzip", gzip(constantValuePacked));
        print("declared_exceptions_jar", declaredExceptionsJar);
        print("declared_exceptions_pack", declaredExceptionsPacked);
        print("declared_exceptions_pack_gzip", gzip(declaredExceptionsPacked));
        print("source_file_jar", sourceFileJar);
        print("source_file_pack", sourceFilePacked);
        print("source_file_pack_gzip", gzip(sourceFilePacked));
        print("signature_jar", signatureJar);
        print("signature_pack", signaturePacked);
        print("signature_pack_gzip", gzip(signaturePacked));
    }
}
