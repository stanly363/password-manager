import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.*;
import java.security.spec.KeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {

    public static void main(String[] args) {
        // Launch the login frame
        javax.swing.SwingUtilities.invokeLater(() -> {
            new LoginFrame();
        });
    }

    
    static class LoginFrame extends JFrame {
        private JTextField usernameField;
        private JPasswordField passwordField;

        public LoginFrame() {
            setTitle("Password Manager - Login");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(350, 200);
            setLocationRelativeTo(null);
            initComponents();
            setVisible(true);
        }

        private void initComponents() {
            JLabel usernameLabel = new JLabel("Username:");
            JLabel passwordLabel = new JLabel("Password:");

            usernameField = new JTextField(15);
            passwordField = new JPasswordField(15);

            JButton loginButton = new JButton("Login");
            JButton registerButton = new JButton("Register");

            loginButton.addActionListener(e -> loginAction());
            registerButton.addActionListener(e -> {
                dispose();
                new RegisterFrame();
            });

            JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();

            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.gridx = 0;
            gbc.gridy = 0;
            panel.add(usernameLabel, gbc);

            gbc.gridx = 1;
            panel.add(usernameField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 1;
            panel.add(passwordLabel, gbc);

            gbc.gridx = 1;
            panel.add(passwordField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 2;
            panel.add(loginButton, gbc);

            gbc.gridx = 1;
            panel.add(registerButton, gbc);

            add(panel);
        }

        private void loginAction() {
            String username = usernameField.getText();
            char[] password = passwordField.getPassword();

            if (User.authenticate(username, new String(password))) {
                JOptionPane.showMessageDialog(this, "Login successful!");
                dispose();
                new PasswordManagerFrame(username);
            } else {
                JOptionPane.showMessageDialog(this, "Invalid credentials", "Error", JOptionPane.ERROR_MESSAGE);
            }
            // Clear password field
            Arrays.fill(password, '0');
        }
    }

    
    static class RegisterFrame extends JFrame {
        private JTextField usernameField;
        private JPasswordField passwordField;
        private JPasswordField confirmPasswordField;

        public RegisterFrame() {
            setTitle("Password Manager - Register");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(350, 250);
            setLocationRelativeTo(null);
            initComponents();
            setVisible(true);
        }

        private void initComponents() {
            JLabel usernameLabel = new JLabel("Username:");
            JLabel passwordLabel = new JLabel("Password:");
            JLabel confirmPasswordLabel = new JLabel("Confirm Password:");

            usernameField = new JTextField(15);
            passwordField = new JPasswordField(15);
            confirmPasswordField = new JPasswordField(15);

            JButton registerButton = new JButton("Register");
            JButton backButton = new JButton("Back");

            registerButton.addActionListener(e -> registerAction());
            backButton.addActionListener(e -> {
                dispose();
                new LoginFrame();
            });

            JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();

            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.gridx = 0;
            gbc.gridy = 0;
            panel.add(usernameLabel, gbc);

            gbc.gridx = 1;
            panel.add(usernameField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 1;
            panel.add(passwordLabel, gbc);

            gbc.gridx = 1;
            panel.add(passwordField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 2;
            panel.add(confirmPasswordLabel, gbc);

            gbc.gridx = 1;
            panel.add(confirmPasswordField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 3;
            panel.add(registerButton, gbc);

            gbc.gridx = 1;
            panel.add(backButton, gbc);

            add(panel);
        }

        private void registerAction() {
            String username = usernameField.getText();
            char[] password = passwordField.getPassword();
            char[] confirmPassword = confirmPasswordField.getPassword();

            if (!Arrays.equals(password, confirmPassword)) {
                JOptionPane.showMessageDialog(this, "Passwords do not match", "Error", JOptionPane.ERROR_MESSAGE);
                Arrays.fill(password, '0');
                Arrays.fill(confirmPassword, '0');
                return;
            }

            if (User.exists(username)) {
                JOptionPane.showMessageDialog(this, "Username already exists", "Error", JOptionPane.ERROR_MESSAGE);
            } else {
                User.register(username, new String(password));
                JOptionPane.showMessageDialog(this, "Registration successful!");
                dispose();
                new LoginFrame();
            }
            Arrays.fill(password, '0');
            Arrays.fill(confirmPassword, '0');
        }
    }

    
    static class User {
        private static final String USER_DATA_FILE = "users.dat";

        public static boolean authenticate(String username, String password) {
            Map<String, String> users = loadUsers();
            String hashedPassword = users.get(username);
            if (hashedPassword != null) {
                return PasswordUtils.verify(password, hashedPassword);
            }
            return false;
        }

        public static void register(String username, String password) {
            Map<String, String> users = loadUsers();
            String hashedPassword = PasswordUtils.hash(password);
            users.put(username, hashedPassword);

            saveUsers(users);
        }

        public static boolean exists(String username) {
            Map<String, String> users = loadUsers();
            return users.containsKey(username);
        }

        @SuppressWarnings("unchecked")
        private static Map<String, String> loadUsers() {
            Map<String, String> users = new HashMap<>();
            File file = new File(USER_DATA_FILE);
            if (file.exists()) {
                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(USER_DATA_FILE))) {
                    users = (Map<String, String>) in.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
            return users;
        }

        private static void saveUsers(Map<String, String> users) {
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(USER_DATA_FILE))) {
                out.writeObject(users);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    
    static class PasswordUtils {
        private static final String SALT = "YourSaltValue"; // Replace with a secure salt

        public static String hash(String password) {
            try {
                byte[] saltBytes = SALT.getBytes(StandardCharsets.UTF_8);
                KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] hashBytes = factory.generateSecret(spec).getEncoded();
                return Base64.getEncoder().encodeToString(hashBytes);
            } catch (Exception e) {
                throw new RuntimeException("Error hashing password", e);
            }
        }

        public static boolean verify(String password, String hashedPassword) {
            String hashedInput = hash(password);
            return hashedInput.equals(hashedPassword);
        }
    }

    
    static class PasswordManagerFrame extends JFrame {
        private String username;
        private List<PasswordEntry> entries;
        private JTable table;
        private PasswordTableModel tableModel;

        public PasswordManagerFrame(String username) {
            this.username = username;
            entries = PasswordEntry.loadEntries(username);
            setTitle("Password Manager - " + username);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(600, 400);
            setLocationRelativeTo(null);
            initComponents();
            setVisible(true);
        }

        private void initComponents() {
            tableModel = new PasswordTableModel(entries);
            table = new JTable(tableModel);

            JButton addButton = new JButton("Add");
            JButton editButton = new JButton("Edit");
            JButton deleteButton = new JButton("Delete");

            addButton.addActionListener(e -> addEntry());
            editButton.addActionListener(e -> editEntry());
            deleteButton.addActionListener(e -> deleteEntry());

            table.addMouseListener(new java.awt.event.MouseAdapter() {
                public void mouseClicked(java.awt.event.MouseEvent evt) {
                    if (evt.getClickCount() == 2) {
                        editEntry();
                    }
                }
            });

            JPanel buttonPanel = new JPanel();
            buttonPanel.add(addButton);
            buttonPanel.add(editButton);
            buttonPanel.add(deleteButton);

            add(new JScrollPane(table), BorderLayout.CENTER);
            add(buttonPanel, BorderLayout.SOUTH);
        }

        private void addEntry() {
            PasswordEntryDialog dialog = new PasswordEntryDialog(this, "Add New Entry", null);
            PasswordEntry newEntry = dialog.getEntry();
            if (newEntry != null) {
                entries.add(newEntry);
                tableModel.fireTableDataChanged();
                PasswordEntry.saveEntries(username, entries);
            }
        }

        private void editEntry() {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                PasswordEntry entry = entries.get(selectedRow);
                PasswordEntryDialog dialog = new PasswordEntryDialog(this, "Edit Entry", entry);
                PasswordEntry updatedEntry = dialog.getEntry();
                if (updatedEntry != null) {
                    entries.set(selectedRow, updatedEntry);
                    tableModel.fireTableDataChanged();
                    PasswordEntry.saveEntries(username, entries);
                }
            } else {
                JOptionPane.showMessageDialog(this, "Please select an entry to edit", "Warning", JOptionPane.WARNING_MESSAGE);
            }
        }

        private void deleteEntry() {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                entries.remove(selectedRow);
                tableModel.fireTableDataChanged();
                PasswordEntry.saveEntries(username, entries);
            } else {
                JOptionPane.showMessageDialog(this, "Please select an entry to delete", "Warning", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    
    static class PasswordEntry implements Serializable {
        private static final long serialVersionUID = 1L;

        private String website;
        private String username;
        private String password;
        private String notes;

        public PasswordEntry(String website, String username, String password, String notes) {
            this.website = website;
            this.username = username;
            this.password = password;
            this.notes = notes;
        }

        
        public String getWebsite() {
            return website;
        }

        public void setWebsite(String website) {
            this.website = website;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getNotes() {
            return notes;
        }

        public void setNotes(String notes) {
            this.notes = notes;
        }

        @SuppressWarnings("unchecked")
        public static List<PasswordEntry> loadEntries(String username) {
            List<PasswordEntry> entries = new ArrayList<>();
            String filePath = username + "_passwords.dat";
            File file = new File(filePath);
            if (file.exists()) {
                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filePath))) {
                    List<PasswordEntry> encryptedEntries = (List<PasswordEntry>) in.readObject();
                    // Decrypt entries
                    entries = EncryptionUtils.decryptEntries(encryptedEntries);
                    System.out.println("Entries loaded from " + file.getAbsolutePath());
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("No entries file found for " + username);
            }
            return entries;
        }

        public static void saveEntries(String username, List<PasswordEntry> entries) {
            String filePath = username + "_passwords.dat";
            // Encrypt entries
            List<PasswordEntry> encryptedEntries = EncryptionUtils.encryptEntries(entries);
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filePath))) {
                out.writeObject(encryptedEntries);
                System.out.println("Entries saved to " + new File(filePath).getAbsolutePath());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    
    static class EncryptionUtils {
        private static final String SECRET_KEY = "1234567890123456"; // Replace with a secure 16-byte key

        public static List<PasswordEntry> encryptEntries(List<PasswordEntry> entries) {
            List<PasswordEntry> encryptedEntries = new ArrayList<>();
            for (PasswordEntry entry : entries) {
                String encryptedPassword = encrypt(entry.getPassword());
                // Create a new PasswordEntry with the encrypted password
                PasswordEntry encryptedEntry = new PasswordEntry(
                        entry.getWebsite(),
                        entry.getUsername(),
                        encryptedPassword,
                        entry.getNotes()
                );
                encryptedEntries.add(encryptedEntry);
            }
            return encryptedEntries;
        }

        public static List<PasswordEntry> decryptEntries(List<PasswordEntry> entries) {
            List<PasswordEntry> decryptedEntries = new ArrayList<>();
            for (PasswordEntry entry : entries) {
                String decryptedPassword = decrypt(entry.getPassword());
                // Create a new PasswordEntry with the decrypted password
                PasswordEntry decryptedEntry = new PasswordEntry(
                        entry.getWebsite(),
                        entry.getUsername(),
                        decryptedPassword,
                        entry.getNotes()
                );
                decryptedEntries.add(decryptedEntry);
            }
            return decryptedEntries;
        }

        public static String encrypt(String data) {
            try {
                SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(encrypted);
            } catch (Exception e) {
                throw new RuntimeException("Error encrypting data", e);
            }
        }

        public static String decrypt(String data) {
            try {
                SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
                return new String(decrypted, StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new RuntimeException("Error decrypting data", e);
            }
        }
    }

    
    static class PasswordEntryDialog extends JDialog {
        private JTextField websiteField;
        private JTextField usernameField;
        private JTextField passwordField;
        private JTextArea notesArea;
        private PasswordEntry entry;

        public PasswordEntryDialog(Frame parent, String title, PasswordEntry entry) {
            super(parent, title, true);
            this.entry = entry;
            initComponents();
            setSize(400, 300);
            setLocationRelativeTo(parent);
            setVisible(true);
        }

        private void initComponents() {
            JLabel websiteLabel = new JLabel("Website:");
            JLabel usernameLabel = new JLabel("Username:");
            JLabel passwordLabel = new JLabel("Password:");
            JLabel notesLabel = new JLabel("Notes:");

            websiteField = new JTextField(20);
            usernameField = new JTextField(20);
            passwordField = new JTextField(20);
            notesArea = new JTextArea(5, 20);

            if (entry != null) {
                websiteField.setText(entry.getWebsite());
                usernameField.setText(entry.getUsername());
                passwordField.setText(entry.getPassword());
                notesArea.setText(entry.getNotes());
            }

            JButton saveButton = new JButton("Save");
            JButton cancelButton = new JButton("Cancel");

            saveButton.addActionListener(e -> saveAction());
            cancelButton.addActionListener(e -> {
                entry = null;
                dispose();
            });

            JPanel panel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();

            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.anchor = GridBagConstraints.WEST;

            gbc.gridx = 0;
            gbc.gridy = 0;
            panel.add(websiteLabel, gbc);

            gbc.gridx = 1;
            panel.add(websiteField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 1;
            panel.add(usernameLabel, gbc);

            gbc.gridx = 1;
            panel.add(usernameField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 2;
            panel.add(passwordLabel, gbc);

            gbc.gridx = 1;
            panel.add(passwordField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            panel.add(notesLabel, gbc);

            gbc.gridx = 1;
            panel.add(new JScrollPane(notesArea), gbc);

            gbc.gridx = 0;
            gbc.gridy = 4;
            gbc.anchor = GridBagConstraints.CENTER;
            panel.add(saveButton, gbc);

            gbc.gridx = 1;
            panel.add(cancelButton, gbc);

            add(panel);
        }

        private void saveAction() {
            String website = websiteField.getText();
            String username = usernameField.getText();
            String password = passwordField.getText();
            String notes = notesArea.getText();

            if (website.isEmpty() || username.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please fill in all required fields", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }

            entry = new PasswordEntry(website, username, password, notes);
            dispose();
        }

        public PasswordEntry getEntry() {
            return entry;
        }
    }

    
    static class PasswordTableModel extends AbstractTableModel {
        private List<PasswordEntry> entries;
        private String[] columnNames = {"Website", "Username"};

        public PasswordTableModel(List<PasswordEntry> entries) {
            this.entries = entries;
        }

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            PasswordEntry entry = entries.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return entry.getWebsite();
                case 1:
                    return entry.getUsername();
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
    }
}
