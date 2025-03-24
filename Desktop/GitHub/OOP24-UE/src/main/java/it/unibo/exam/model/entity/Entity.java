package main.java.it.unibo.exam.model.entity;

import java.awt.Rectangle;

public abstract class Entity {
    protected int x;
    protected int y;
    protected int width;
    protected int height;
    protected Rectangle hitbox;
    
    public int getX() {
        return x;
    }
    
    public void setX(int x) {
        this.x = x;
        updateHitbox();
    }
    
    public int getY() {
        return y;
    }
    
    public void setY(int y) {
        this.y = y;
        updateHitbox();
    }
    
    public int getWidth() {
        return width;
    }
    
    public int getHeight() {
        return height;
    }
    
    public Rectangle getHitbox() {
        return hitbox;
    }
    
    protected void updateHitbox() {
        if (hitbox != null) {
            hitbox.x = x;
            hitbox.y = y;
        }
    }
}