package main.java.it.unibo.exam;

import javax.swing.JFrame;
import main.java.it.unibo.exam.controller.game.GameController;
import main.java.it.unibo.exam.controller.input.KeyHandler;
import main.java.it.unibo.exam.model.game.GameState;
import main.java.it.unibo.exam.view.panel.GamePanel;

public final class Main {
    private Main() {
        throw new UnsupportedOperationException("Main class cannot be instantiated");
    }
    
    public static void main(final String[] args) {
        // Initialize components
        KeyHandler keyHandler = new KeyHandler();
        GameState gameState = new GameState();
        GameController gameController = new GameController(gameState, keyHandler);
        
        // Set up UI
        final JFrame window = new JFrame();
        window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        window.setResizable(false);
        window.setTitle("UNIBO");
        
        final GamePanel gamePanel = new GamePanel(gameController);
        window.add(gamePanel);
        window.pack();
        window.setLocationRelativeTo(null);
        window.setVisible(true);
        gamePanel.startGameThread();
    }
}

/***
 * @Copyright
 *            Simone Brunelli - Purp7ePi3 - simone.brunelli3@studio.unibo.it
 *            Tommaso Nori - tommaso.nori@studio.unibo.it
 *            Daniel Horna - d.alejandrohorna@gmail.com
 *            Davide Amantini - AmantiniDavide - davide.amantini@studio.unibo.it
 *            Mattia Pozzati - PozzatiMattia - mattia.pozzati3@studio.unibo.it
 */