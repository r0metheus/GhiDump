package ghidump.communication;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.exceptions.JedisException;

import java.time.Duration;

/**
 * Publishes analysis results to a Redis Pub/Sub channel.
 * Uses connection pooling for efficient resource management.
 */
public class RedisPublisher implements AutoCloseable {
    
    private static final String CHANNEL_NAME = "ghidump:tasks";
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    
    private final JedisPool jedisPool;
    private final String channelName;
    
    /**
     * Create a RedisPublisher with default settings (localhost:6379).
     */
    public RedisPublisher() {
        this("localhost", 6379, CHANNEL_NAME);
    }
    
    /**
     * Create a RedisPublisher with custom host and port.
     * 
     * @param host Redis server host
     * @param port Redis server port
     */
    public RedisPublisher(String host, int port) {
        this(host, port, CHANNEL_NAME);
    }
    
    /**
     * Create a RedisPublisher with custom settings.
     * 
     * @param host Redis server host
     * @param port Redis server port
     * @param channelName Pub/Sub channel name
     */
    public RedisPublisher(String host, int port, String channelName) {
        this.channelName = channelName;
        
        // Configure connection pool
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(10);
        poolConfig.setMaxIdle(5);
        poolConfig.setMinIdle(1);
        poolConfig.setTestOnBorrow(true);
        poolConfig.setTestOnReturn(true);
        poolConfig.setTestWhileIdle(true);
        poolConfig.setBlockWhenExhausted(true);
        poolConfig.setMaxWait(Duration.ofMillis(DEFAULT_TIMEOUT_MS));
        
        // Create the pool
        this.jedisPool = new JedisPool(poolConfig, host, port, DEFAULT_TIMEOUT_MS);
    }
    
    /**
     * Publish a MessagePack payload to the Redis channel.
     * 
     * @param payload The serialized MessagePack data
     * @throws RuntimeException if publishing fails
     */
    public void publish(byte[] payload) {
        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("Payload cannot be null or empty");
        }
        
        // Use try-with-resources to ensure connection is returned to pool
        try (Jedis jedis = jedisPool.getResource()) {
            long subscriberCount = jedis.publish(channelName.getBytes(), payload);
            
            // Log the publish result (in production, use proper logging)
            System.out.println(String.format(
                "Published %d bytes to channel '%s', received by %d subscribers",
                payload.length, channelName, subscriberCount));
                
        } catch (JedisException e) {
            throw new RuntimeException(
                "Failed to publish to Redis channel: " + channelName, e);
        }
    }
    
    /**
     * Test the Redis connection.
     * 
     * @return true if connection is successful
     */
    public boolean testConnection() {
        try (Jedis jedis = jedisPool.getResource()) {
            String pong = jedis.ping();
            return "PONG".equals(pong);
        } catch (JedisException e) {
            return false;
        }
    }
    
    /**
     * Close the Redis connection pool.
     * Should be called when the publisher is no longer needed.
     */
    public void close() {
        if (jedisPool != null && !jedisPool.isClosed()) {
            jedisPool.close();
        }
    }
    
    /**
     * Get statistics about the connection pool.
     * 
     * @return Pool statistics as a string
     */
    public String getPoolStats() {
        return String.format(
            "Active: %d, Idle: %d, Waiters: %d",
            jedisPool.getNumActive(),
            jedisPool.getNumIdle(),
            jedisPool.getNumWaiters()
        );
    }
}