import java.awt.*;
import java.awt.event.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import net.miginfocom.swing.MigLayout;

public final class Cryptosystem extends JFrame implements ActionListener {

    private JPanel asymmetricPanel;
    private JPanel symmetricPanel;
    private final JPanel mainPanel, contentPanel;
    private JPanel currentPanel;
    private final JRadioButton asymmetricRadio, symmetricRadio;
    private final CardLayout crdLyout;
    private JTextArea messageArea, msgArea, outputArea, encryptedTextArea, decryptedTextArea;
    private JTextField keyField;
    private JButton encryptButton, decryptButton, encryptionButton, generateButton;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public Cryptosystem() {
        setTitle("CryptoSystem App");
        setSize(500, 500);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.setBackground(Color.WHITE);

        GridBagConstraints gbc = new GridBagConstraints();

        gbc.insets = new Insets(5, 5, 5, 5);

        JLabel algoLabel = new JLabel("Select Encryption Algorithm:");
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(algoLabel, gbc);

        asymmetricRadio = new JRadioButton("Asymmetric");
        asymmetricRadio.setSelected(true);
        asymmetricRadio.addActionListener(this);
        symmetricRadio = new JRadioButton("Symmetric");
        symmetricRadio.addActionListener(this);

        ButtonGroup group = new ButtonGroup();
        group.add(asymmetricRadio);
        group.add(symmetricRadio);

        JPanel algoPanel = new JPanel(new GridLayout(1, 2));
        algoPanel.add(asymmetricRadio);
        algoPanel.add(symmetricRadio);
        gbc.gridx = 1;
        gbc.gridy = 0;
        panel.add(algoPanel, gbc);

        asymmetricPanel = new JPanel(new MigLayout());
        symmetricPanel = new JPanel(new MigLayout());
        currentPanel = asymmetricPanel; // Default panel is asymmetric

        mainPanel = new JPanel();
        contentPanel = new JPanel();

        crdLyout = new CardLayout();

        initSymmetricComponent();
        initAsymmetricComponent();

        contentPanel.setLayout(crdLyout);
        contentPanel.add(asymmetricPanel, "1");
        contentPanel.add(symmetricPanel, "2");

        crdLyout.show(contentPanel, "1");


        mainPanel.setLayout(new MigLayout("fill, insets 0"));
        mainPanel.setBackground(Color.WHITE);
        mainPanel.add(panel, "wrap");
        mainPanel.add(contentPanel, "push, grow");
        add(mainPanel);

        setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Cryptosystem::new);
    }

    public void initSymmetricComponent() {
        JLabel msgLabel = new JLabel("Message:");
        JLabel keyLabel = new JLabel("Secret Key:");
        JLabel outputLabel = new JLabel("Output:");

        messageArea = new JTextArea(5, 50);
        outputArea = new JTextArea(5, 50);
        keyField = new JTextField();
        keyField.setBorder(null);

        // Set a new preferred size to increase the height of the keyField
        Dimension keyFieldDimension = new Dimension(keyField.getPreferredSize().width, 30);
        keyField.setPreferredSize(keyFieldDimension);

        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        encryptButton.addActionListener(this);
        decryptButton.addActionListener(this);

        symmetricPanel.add(msgLabel, "wrap, gapbottom 5");
        symmetricPanel.add(messageArea, "wrap, gapbottom 10");
        symmetricPanel.add(keyLabel, "wrap, gapbottom 5");
        symmetricPanel.add(keyField, "grow, wrap, gapbottom 10");
        symmetricPanel.add(encryptButton, "span, split 2, growx, gaptop 5");
        symmetricPanel.add(decryptButton, "growx, wrap, gapbottom 15");
        symmetricPanel.add(outputLabel, "wrap, gapbottom 5");
        symmetricPanel.add(outputArea, "growx");
    }

    public void initAsymmetricComponent() {
        JLabel keypairLabel = new JLabel("Generate Key Pair");

        JLabel msgLabel = new JLabel("Message:");
        msgArea = new JTextArea(5, 50);

        generateButton = new JButton("Generate");
        generateButton.addActionListener(this);

        JLabel senderLabel = new JLabel("Sender Encrypted Message: ");
        JLabel receiverLabel = new JLabel("Receiver Original Message: ");

        encryptedTextArea = new JTextArea(5, 25);
        encryptedTextArea.setWrapStyleWord(true);
        encryptedTextArea.setLineWrap(true);
        decryptedTextArea = new JTextArea(5, 25);
        decryptedTextArea.setWrapStyleWord(true);
        decryptedTextArea.setLineWrap(true);

        encryptionButton = new JButton("Encrypt");
        encryptionButton.addActionListener(this);

        asymmetricPanel.add(keypairLabel, "growx, gapbottom 15");
        asymmetricPanel.add(generateButton, "growx, wrap, gapbottom 15");
        asymmetricPanel.add(msgLabel, "wrap, gapbottom 5");
        asymmetricPanel.add(msgArea, "wrap, gapbottom 10");
        asymmetricPanel.add(senderLabel, "span, split 2, growx");
        asymmetricPanel.add(receiverLabel, "growx, wrap, gapbottom 5");
        asymmetricPanel.add(encryptedTextArea, "span, split 2, growx");
        asymmetricPanel.add(decryptedTextArea, "growx, wrap, gapbottom 15");
        asymmetricPanel.add(encryptionButton, "growx");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == asymmetricRadio) {
            crdLyout.show(contentPanel, "1");
        } else if (e.getSource() == symmetricRadio) {
            crdLyout.show(contentPanel, "2");
        } else if (e.getSource() == encryptButton) {
            String message = messageArea.getText();
            String key = keyField.getText();

            if (message.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter the message!");
                return;
            } else if (key.length() != 16 && key.length() != 24 && key.length() != 32) {
                JOptionPane.showMessageDialog(this, "Invalid key length. Key must be 16, 24, or 32 characters long.");
                return;
            } else {
                // Encrypt the message using AES and the provided key
                String encryptedMessage = encryptAES(message, key);

                // Display the encrypted message
                outputArea.setText("Encrypted Message:\n" + encryptedMessage);
            }
        } else if (e.getSource() == encryptionButton) {
            encryptRSAMessage();
        } else if (e.getSource() == decryptButton) {
            String encryptedMessage = outputArea.getText();
            // Remove the prefix "Encrypted Message:\n" from the encryptedMessage string
            encryptedMessage = encryptedMessage.replace("Encrypted Message:\n", "");
            String key = keyField.getText();

            // Check key length
            if (key.length() != 16 && key.length() != 24 && key.length() != 32) {
                JOptionPane.showMessageDialog(this, "Invalid key length. Key must be 16, 24, or 32 characters long.");
                return;
            }

            // Decrypt the message using AES and the provided key
            String decryptedMessage = decryptAES(encryptedMessage, key);

            // Display the decrypted message
            outputArea.setText("Decrypted Message:\n" + decryptedMessage);
        } else if (e.getSource() == generateButton) {
            generateKeys();
        }
    }

    // AES encryption method
    private String encryptAES(String message, String key) {
        try {
            // Convert the key into a 128-bit AES key
            byte[] keyBytes = key.getBytes();
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            // Create AES cipher instance
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Encrypt the message
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());

            // Convert the encrypted bytes to a hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : encryptedBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    // AES decryption method
    private String decryptAES(String encryptedMessage, String key) {
        try {
            // Convert the key into a 128-bit AES key
            byte[] keyBytes = key.getBytes();
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            // Create AES cipher instance
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Convert the hexadecimal string to bytes
            byte[] encryptedBytes = new byte[encryptedMessage.length() / 2];
            for (int i = 0; i < encryptedMessage.length(); i += 2) {
                int hexValue = Integer.parseInt(encryptedMessage.substring(i, i + 2), 16);
                encryptedBytes[i / 2] = (byte) hexValue;
            }

            // Decrypt the message
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Convert the decrypted bytes to a string
            return new String(decryptedBytes);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    private void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            JOptionPane.showMessageDialog(asymmetricPanel, "Key Pair Generated Successfully");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(asymmetricPanel, "Error generating key pair: " + e.getMessage());
        }
    }

    private void encryptRSAMessage() {
        try {
            if (publicKey == null) {
                JOptionPane.showMessageDialog(asymmetricPanel, "Please generate key pair first");
                return;
            }

            if (msgArea.getText().isEmpty()) {
                JOptionPane.showMessageDialog(asymmetricPanel, "Please enter a message to encrypt");
                return;
            }

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(msgArea.getText().getBytes());
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
            encryptedTextArea.setText(encryptedMessage);

            decryptRSAMessage(encryptedMessage);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(asymmetricPanel, "Error encrypting message: " + e.getMessage());
        }
    }

    private void decryptRSAMessage(String encryptedMessage) {
        try {
            if (privateKey == null) {
                JOptionPane.showMessageDialog(asymmetricPanel, "Private key is missing");
                return;
            }

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedMessage = new String(decryptedBytes);
            decryptedTextArea.setText(decryptedMessage);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(asymmetricPanel, "Error decrypting message: " + e.getMessage());
        }
    }
}

