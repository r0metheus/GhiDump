package ghidump;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidump.communication.RedisPublisher;
import ghidump.model.AnalysisResult;
import ghidump.serialization.MessagePackSerializer;

import java.io.IOException;

/**
 * Ghidump 2.0 Plugin - Automatically exports and publishes analysis results to Redis
 * when Ghidra completes analysis of a binary.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "ghidump",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidump 2.0 - Export analysis to Redis",
    description = "Automatically exports binary analysis results to Redis using MessagePack when analysis completes.",
    servicesRequired = { },
    servicesProvided = { },
    eventsConsumed = { }
)
//@formatter:on
public class GhidumpPlugin extends ProgramPlugin {

    private static final String PLUGIN_NAME = "Ghidump 2.0";
    private String redisHost = "localhost";
    private int redisPort = 6379;
    private boolean enabled = true;

    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public GhidumpPlugin(PluginTool tool) {
        super(tool);
        
        // Initialize configuration from tool options
        initializeOptions();
        
        Msg.info(this, PLUGIN_NAME + " plugin initialized");
        Msg.info(this, "Redis endpoint: " + redisHost + ":" + redisPort);
    }

    @Override
    public void init() {
        super.init();
        Msg.info(this, PLUGIN_NAME + " plugin started and ready");
    }

    @Override
    protected void programActivated(Program program) {
        // Program activated - trigger export
        Msg.info(this, PLUGIN_NAME + " program activated: " + program.getName());
        // Automatically export when program is activated
        exportAnalysisResults(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        // Program deactivated
        Msg.info(this, PLUGIN_NAME + " program deactivated: " + program.getName());
    }

    private void exportAnalysisResults(Program program) {
        if (!enabled) {
            Msg.info(this, PLUGIN_NAME + " is disabled, skipping export");
            return;
        }

        Msg.info(this, "=" .repeat(60));
        Msg.info(this, PLUGIN_NAME + " Analysis completed for: " + program.getName());
        Msg.info(this, "Starting automatic export to Redis...");
        
        try {
            // Create task monitor for the export process
            TaskMonitor monitor = TaskMonitor.DUMMY;
            
            // Step 1: Build the normalized data model
            Msg.info(this, "Building normalized data model...");
            DataModeler modeler = new DataModeler(program, monitor);
            AnalysisResult result = modeler.buildModel();
            
            // Log statistics
            int functionCount = result.functions().size();
            int blockCount = result.basicBlocks().size();
            int stringCount = result.stringTable().size();
            
            Msg.info(this, String.format(
                "Model built: %d functions, %d basic blocks, %d unique strings",
                functionCount, blockCount, stringCount));
            
            // Step 2: Serialize to MessagePack
            Msg.info(this, "Serializing to MessagePack...");
            MessagePackSerializer serializer = new MessagePackSerializer();
            byte[] payload = serializer.serialize(result);
            
            Msg.info(this, String.format(
                "Serialized to %d bytes (%.2f KB)",
                payload.length, payload.length / 1024.0));
            
            // Step 3: Publish to Redis
            Msg.info(this, "Publishing to Redis at " + redisHost + ":" + redisPort + "...");
            try (RedisPublisher publisher = new RedisPublisher(redisHost, redisPort)) {
                // Test connection first
                if (!publisher.testConnection()) {
                    throw new RuntimeException(
                        "Cannot connect to Redis at " + redisHost + ":" + redisPort);
                }
                
                publisher.publish(payload);
                Msg.info(this, "Successfully published to Redis channel 'ghidump:tasks'");
            }
            
            // Success summary
            Msg.info(this, "=" .repeat(60));
            Msg.info(this, PLUGIN_NAME + " Export Complete!");
            Msg.info(this, "Binary: " + result.binaryName());
            Msg.info(this, "MD5: " + result.binaryMd5());
            Msg.info(this, "Functions: " + functionCount);
            Msg.info(this, "Basic Blocks: " + blockCount);
            Msg.info(this, "String Table: " + stringCount + " entries");
            Msg.info(this, "Payload Size: " + String.format("%.2f KB", payload.length / 1024.0));
            Msg.info(this, "=" .repeat(60));
            
        } catch (Exception e) {
            Msg.error(this, PLUGIN_NAME + " export failed: " + e.getMessage(), e);
        }
    }

    private void initializeOptions() {
        ToolOptions options = tool.getOptions("Ghidump");
        
        // Register options with defaults
        options.registerOption("Redis Host", "localhost", null, 
            "Redis server hostname or IP address");
        options.registerOption("Redis Port", 6379, null, 
            "Redis server port");
        options.registerOption("Enabled", true, null,
            "Enable automatic export on analysis completion");
        
        // Load current values
        redisHost = options.getString("Redis Host", "localhost");
        redisPort = options.getInt("Redis Port", 6379);
        enabled = options.getBoolean("Enabled", true);
        
        // Listen for option changes
        options.addOptionsChangeListener(this::optionsChanged);
    }

    private void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
        switch (optionName) {
            case "Redis Host":
                redisHost = (String) newValue;
                Msg.info(this, "Redis host changed to: " + redisHost);
                break;
            case "Redis Port":
                redisPort = (Integer) newValue;
                Msg.info(this, "Redis port changed to: " + redisPort);
                break;
            case "Enabled":
                enabled = (Boolean) newValue;
                Msg.info(this, PLUGIN_NAME + " " + (enabled ? "enabled" : "disabled"));
                break;
        }
    }

    @Override
    protected void dispose() {
        Msg.info(this, PLUGIN_NAME + " plugin disposed");
        super.dispose();
    }
}