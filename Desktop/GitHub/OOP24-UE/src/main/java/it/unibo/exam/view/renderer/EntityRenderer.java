package main.java.it.unibo.exam.view.renderer;

import java.awt.Color;
import java.awt.Graphics2D;
import main.java.it.unibo.exam.model.entity.Player;

public class EntityRenderer {
    public void renderPlayer(Graphics2D g2, Player player) {
        g2.setColor(Color.WHITE);
        g2.fillRect(player.getX(), player.getY(), player.getWidth(), player.getHeight());
    }
}