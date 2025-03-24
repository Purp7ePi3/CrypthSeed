package main.java.it.unibo.exam.model.entity;

import java.awt.Rectangle;
import main.java.it.unibo.exam.view.panel.GamePanel;

public class Player extends Entity {
    private int speed;
    
    public Player(int x, int y, int speed) {
        this.x = x;
        this.y = y;
        this.width = GamePanel.TILE_SIZE;
        this.height = GamePanel.TILE_SIZE;
        this.speed = speed;
        this.hitbox = new Rectangle(x, y, width, height);
    }
    
    public void move(boolean up, boolean down, boolean left, boolean right, double deltaTime) {
        int currentSpeedX = 0;
        int currentSpeedY = 0;
        
        if (down) currentSpeedY = speed;
        if (up) currentSpeedY = -speed;
        if (left) currentSpeedX = -speed;
        if (right) currentSpeedX = speed;
        
        x += currentSpeedX * deltaTime * speed;
        y += currentSpeedY * deltaTime * speed;
        
        // Boundary checks
        if (x < 0) x = 0;
        if (x > GamePanel.ORIGINAL_WIDTH - width) x = GamePanel.ORIGINAL_WIDTH - width;
        if (y < 0) y = 0;
        if (y > GamePanel.ORIGINAL_HEIGHT - height) y = GamePanel.ORIGINAL_HEIGHT - height;
        
        updateHitbox();
    }
    
    public int getSpeed() {
        return speed;
    }
}