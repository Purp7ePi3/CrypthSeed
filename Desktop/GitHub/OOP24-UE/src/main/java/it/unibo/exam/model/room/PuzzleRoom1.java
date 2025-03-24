package main.java.it.unibo.exam.model.room;

import java.awt.Color;
import java.awt.Graphics2D;
import java.util.List;
import main.java.it.unibo.exam.controller.input.KeyHandler;
import main.java.it.unibo.exam.model.entity.Door;
import main.java.it.unibo.exam.model.game.GameState;
import main.java.it.unibo.exam.view.panel.GamePanel;

public class PuzzleRoom1 extends Room implements PuzzleRoom {
    private boolean puzzleSolved = false;
    private final GameState gameState;
    
    public PuzzleRoom1(final List<Door> doors, final GameState gameState) {
        super(Color.GRAY, doors);
        this.gameState = gameState;
    }
    
    @Override
    public void updatePuzzleLogic(final KeyHandler keyHandler) {
        int playerX = gameState.getPlayer().getX();
        int playerY = gameState.getPlayer().getY();
        
        if (!getDoors().isEmpty()) {
            Door firstDoor = getDoors().get(0);
            
            if (playerX == 0 && playerY == 0 && keyHandler.interactPressed) {
                puzzleSolved = true;
                firstDoor.setSolved(true);
                // Update the door in the main room
                gameState.updateDoorState(1, true); // 1 is the index of this puzzle room
                // Change room color
                setBackgroundColor(Color.GREEN);
            }
        }
    }
    
    @Override
    public void draw(final Graphics2D g2) {
        g2.setColor(getBackgroundColor());
        g2.fillRect(0, 0, GamePanel.ORIGINAL_WIDTH, GamePanel.ORIGINAL_HEIGHT);
        
        // Draw doors
        for (Door door : getDoors()) {
            g2.setColor(door.isSolved() ? Color.GREEN : Color.RED);
            g2.fillRect(door.getX(), door.getY(), door.getWidth(), door.getHeight());
        }
        
        if (puzzleSolved) {
            g2.setColor(Color.WHITE);
            g2.setFont(g2.getFont().deriveFont(24f));
            g2.drawString("Puzzle Solved!", GamePanel.ORIGINAL_WIDTH / 2 - 80, GamePanel.ORIGINAL_HEIGHT / 2);
        }
    }
    
    @Override
    public boolean isPuzzleSolved() {
        return puzzleSolved;
    }
}