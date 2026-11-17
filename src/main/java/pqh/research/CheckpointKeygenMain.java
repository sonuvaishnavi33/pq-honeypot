package pqh.research;

import java.io.IOException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;

/** Generates ML-DSA-65 key files without printing key material. */
public final class CheckpointKeygenMain {
  private CheckpointKeygenMain() {}

  public static void main(String[] args) throws IOException {
    if (args.length != 2) {
      throw new IllegalArgumentException("usage: CheckpointKeygenMain <private-key-file> <public-key-file>");
    }
    Path privateFile = Path.of(args[0]).toAbsolutePath().normalize();
    Path publicFile = Path.of(args[1]).toAbsolutePath().normalize();
    if (privateFile.equals(publicFile) || Files.exists(privateFile) || Files.exists(publicFile)) {
      throw new IllegalArgumentException("key paths must be different and must not already exist");
    }
    if (privateFile.getParent() != null) Files.createDirectories(privateFile.getParent());
    if (publicFile.getParent() != null) Files.createDirectories(publicFile.getParent());

    var pair = CheckpointSigner.generate();
    byte[] privateBytes = Base64.getEncoder().encode(pair.getPrivate().getEncoded());
    byte[] publicBytes = Base64.getEncoder().encode(pair.getPublic().getEncoded());
    try {
      Files.write(publicFile, publicBytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
      Files.write(privateFile, privateBytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
      try {
        restrictPrivateFile(privateFile);
      } catch (IOException | UnsupportedOperationException ex) {
        Files.deleteIfExists(privateFile);
        throw ex;
      }
    } finally {
      Arrays.fill(privateBytes, (byte) 0);
      Arrays.fill(publicBytes, (byte) 0);
    }
    System.out.println("Generated ML-DSA-65 checkpoint key files:");
    System.out.println("Private key: " + privateFile);
    System.out.println("Public key: " + publicFile);
    System.out.println("The private-key file is restricted to its owner.");
  }

  private static void restrictPrivateFile(Path privateFile) throws IOException {
    try {
      Files.setPosixFilePermissions(privateFile,
          EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
      return;
    } catch (UnsupportedOperationException ignored) {
      AclFileAttributeView acl = Files.getFileAttributeView(privateFile, AclFileAttributeView.class);
      if (acl == null) throw new IOException("filesystem does not support private-key ACLs");
      UserPrincipal owner = Files.getOwner(privateFile);
      AclEntry ownerOnly = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
          .setPermissions(EnumSet.allOf(AclEntryPermission.class)).build();
      acl.setAcl(List.of(ownerOnly));
    }
  }
}
