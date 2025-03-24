package main.java.it.unibo.exam.controller.game;

import main.java.it.unibo.exam.controller.input.KeyHandler;
import main.java.it.unibo.exam.model.entity.Door;
import main.java.it.unibo.exam.model.entity.Player;
import main.java.it.unibo.exam.model.game.GameState;
import main.java.it.unibo.exam.model.room.PuzzleRoom;
import main.java.it.unibo.exam.model.room.Room;
import main.java.it.unibo.exam.view.panel.GamePanel;

public class GameController {
    private GameState gameState;
    private KeyHandler keyHandler;
    private int fps;
    private long lastFpsTime;
    private int frameCount;
    private long lastUpdateTime;

    public GameController(GameState gameState, KeyHandler keyHandler) {
        this.gameState = gameState;
        this.keyHandler = keyHandler;
        this.fps = 0;
        this.lastFpsTime = 0;
        this.frameCount = 0;
        this.lastUpdateTime = System.nanoTime(); 
    }
    
    public void update(double deltaTime) {
        long currentTime = System.nanoTime();
        deltaTime = (currentTime - lastUpdateTime) / 1_000_000_000.0;
        lastUpdateTime = currentTime;
        // Update player movement
        Player player = gameState.getPlayer();
        player.move(keyHandler.upPressed, keyHandler.downPressed, 
                   keyHandler.leftPressed, keyHandler.rightPressed, deltaTime);
        
        // Get current room
        Room currentRoom = gameState.getCurrentRoom();
        
        // Update puzzle logic if current room is a puzzle room
        if (currentRoom instanceof PuzzleRoom) {
            ((PuzzleRoom) currentRoom).updatePuzzleLogic(keyHandler);
        }
        
        // Check door interactions
        for (Door door : currentRoom.getDoors()) {
            if (door.isPlayerNearby(player.getX(), player.getY()) && keyHandler.interactPressed) {
                gameState.setLastInteraction("Interacted with: " + door.getName());
                
                /*
                 * TOGLIERE IL COMMENTO A QUESTA PARTE SE UNA VOLTA RISOLTO NON SI POSSA PIù
                 * ANDARE NELLA STANZA
                 */
                /*
                 * if (!door.isSolved() || door.getTargetRoomIndex() == 0) {
                 * gameState.setCurrentRoomIndex(door.getTargetRoomIndex());
                 * player.setX(GamePanel.ORIGINAL_WIDTH / 2 - GamePanel.TILE_SIZE / 2);
                 * player.setY(GamePanel.ORIGINAL_HEIGHT / 2 - GamePanel.TILE_SIZE / 2);
                 * } else {
                 * gameState.setLastInteraction("The puzzle is already solved!");
                 * }
                 */
                
                gameState.setCurrentRoomIndex(door.getTargetRoomIndex());
                player.setX(GamePanel.ORIGINAL_WIDTH / 2 - GamePanel.TILE_SIZE / 2);
                player.setY(GamePanel.ORIGINAL_HEIGHT / 2 - GamePanel.TILE_SIZE / 2);
                break;
            }
        }
    }
    
    public void updateFPS() {
        frameCount++;
        if (System.currentTimeMillis() - lastFpsTime >= 1000) {
            fps = frameCount;
            frameCount = 0;
            lastFpsTime = System.currentTimeMillis();
        }
    }
    
    public GameState getGameState() {
        return gameState;
    }
    
    public int getFPS() {
        return fps;
    }
    
    public void setLastFpsTime(long time) {
        this.lastFpsTime = time;
    }
    
    public void resetFrameCount() {
        this.frameCount = 0;
    }
}