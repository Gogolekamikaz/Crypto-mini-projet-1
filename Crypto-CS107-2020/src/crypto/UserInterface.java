package crypto;

import javax.swing.*;
import java.awt.*;

public class UserInterface {

    private JLabel Title;
    private JTextField textField1;
    private JPanel Window;

    public UserInterface() {

    }

    public static void main(String[] args) {
        JFrame window = new JFrame("Crypto");
        window.setContentPane(new UserInterface().Window);
        window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        window.pack();
        window.setVisible(true);
    }
}
