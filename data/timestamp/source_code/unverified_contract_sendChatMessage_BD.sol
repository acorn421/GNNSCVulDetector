/*
 * ===== SmartInject Injection Details =====
 * Function      : sendChatMessage
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing an anti-spam system that relies on block.timestamp for cooldown periods and spam scoring. The vulnerability requires multiple transactions to exploit as the spam score accumulates over time and affects future message sending capabilities. Attackers can manipulate block timestamps across multiple transactions to bypass cooldowns and spam protection mechanisms.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables:**
 *    - `lastMessageTime[address]`: Tracks when each address last sent a message
 *    - `messageSpamScore[address]`: Accumulates spam score over multiple transactions
 *    - `COOLDOWN_PERIOD`: 30-second cooldown between messages
 *    - `SPAM_THRESHOLD`: Maximum allowed spam score before penalties
 * 
 * 2. **Timestamp-Dependent Logic:**
 *    - Basic cooldown check: `require(block.timestamp >= lastMessageTime[msg.sender] + COOLDOWN_PERIOD)`
 *    - Spam score calculation based on time differences using `block.timestamp`
 *    - Progressive penalty system that increases cooldown based on accumulated spam score
 *    - Spam score reduction over time to reward good behavior
 * 
 * 3. **State Persistence:**
 *    - `lastMessageTime` is updated on every message send
 *    - `messageSpamScore` persists and accumulates across transactions
 *    - Both variables affect future function calls
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Attacker sends first message, `lastMessageTime` is set to current `block.timestamp`
 * 2. **Transaction 2**: Attacker attempts to send second message quickly, but cooldown prevents it
 * 3. **Transaction 3**: Attacker collaborates with miner or uses timestamp manipulation to set `block.timestamp` to bypass cooldown
 * 4. **Transaction 4**: Repeated timestamp manipulation allows bypassing spam score accumulation
 * 5. **Transaction 5+**: Attacker can send unlimited messages by manipulating timestamps across multiple blocks
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * - **State Accumulation**: The spam score builds up over multiple function calls
 * - **Cooldown Persistence**: The `lastMessageTime` state persists between transactions
 * - **Progressive Penalties**: Higher spam scores require longer cooldowns, creating a multi-transaction attack surface
 * - **Timestamp Manipulation**: Requires coordination across multiple blocks to consistently manipulate timestamps
 * - **Score Reset Mechanism**: The spam score reduction over time requires multiple transactions to exploit effectively
 * 
 * **Vulnerability Exploitation Methods:**
 * 
 * 1. **Miner Collusion**: Miners can manipulate `block.timestamp` within the 15-second tolerance
 * 2. **Timestamp Drift**: Exploiting natural timestamp variations between blocks
 * 3. **Race Conditions**: Multiple transactions in different blocks with manipulated timestamps
 * 4. **State Poisoning**: Building up spam score deliberately then resetting it through timestamp manipulation
 */
pragma solidity ^0.4.17;

contract PyramidGame
{
    /////////////////////////////////////////////
    // Game parameters
    uint256 private constant BOTTOM_LAYER_BET_AMOUNT = 0.005 ether;
    uint256 private adminFeeDivisor; // e.g. 100 means a 1% fee, 200 means a 0.5% fee
    
    /////////////////////////////////////////////
    // Game owner
    address private administrator;
    
    /////////////////////////////////////////////
    // Pyramid grid data
    //
    // The uint32 is the coordinates.
    // It consists of two uint16's:
    // The x is the most significant 2 bytes (16 bits)
    // The y is the least significant 2 bytes (16 bits)
    // x = coordinates >> 16
    // y = coordinates & 0xFFFF
    // coordinates = (x << 16) | y
    // x is a 16-bit unsigned integer
    // y is a 16-bit unsigned integer
    mapping(uint32 => address) public coordinatesToAddresses;
    uint32[] public allBlockCoordinates;
    
    // In the user interface, the rows of blocks will be
    // progressively shifted more to the right, as y increases
    // 
    // For example, these blocks in the contract's coordinate system:
    //         ______
    //      2 |__A__|______
    // /|\  1 |__B__|__D__|______
    //  |   0 |__C__|__E__|__F__|
    //  y        0     1     2
    // 
    //        x -->
    // 
    // 
    // Become these blocks in the user interface:
    //    __        ______
    //    /|     __|__A__|___
    //   /    __|__B__|__D__|___
    //  y    |__C__|__E__|__F__|
    // 
    //   x -->
    // 
    // 
    
    /////////////////////////////////////////////
    // Address properties
    mapping(address => uint256) public addressesToTotalWeiPlaced;
    mapping(address => uint256) public addressBalances;
    
    ////////////////////////////////////////////
    // Game Constructor
    function PyramidGame() public
    {
        administrator = msg.sender;
        adminFeeDivisor = 200; // Default fee is 0.5%
        
        // The administrator gets a few free chat messages :-)
        addressesToChatMessagesLeft[administrator] += 5;
        
        // Set the first block in the middle of the bottom row
        coordinatesToAddresses[uint32(1 << 15) << 16] = msg.sender;
        allBlockCoordinates.push(uint32(1 << 15) << 16);
    }
    
    ////////////////////////////////////////////
    // Pyramid grid reading functions
    function getBetAmountAtLayer(uint16 y) public pure returns (uint256)
    {
        // The minimum bet doubles every time you go up 1 layer
        return BOTTOM_LAYER_BET_AMOUNT * (uint256(1) << y);
    }
    
    function isThereABlockAtCoordinates(uint16 x, uint16 y) public view returns (bool)
    {
        return coordinatesToAddresses[(uint32(x) << 16) | uint16(y)] != 0;
    }
    
    function getTotalAmountOfBlocks() public view returns (uint256)
    {
        return allBlockCoordinates.length;
    }
    
    ////////////////////////////////////////////
    // Pyramid grid writing functions
    function placeBlock(uint16 x, uint16 y) external payable
    {
        // You may only place a block on an empty spot
        require(!isThereABlockAtCoordinates(x, y));
        
        // Add the transaction amount to the person's balance
        addressBalances[msg.sender] += msg.value;
        
        // Calculate the required bet amount at the specified layer
        uint256 betAmount = getBetAmountAtLayer(y);

        // If the block is at the lowest layer...
        if (y == 0)
        {
            // There must be a block to the left or to the right of it
            require(isThereABlockAtCoordinates(x-1, y) ||
                    isThereABlockAtCoordinates(x+1, y));
        }
        
        // If the block is NOT at the lowest layer...
        else
        {
            // There must be two existing blocks below it:
            require(isThereABlockAtCoordinates(x  , y-1) &&
                    isThereABlockAtCoordinates(x+1, y-1));
        }
        
        // Subtract the bet amount from the person's balance
        addressBalances[msg.sender] -= betAmount;
        
        // Place the block
        coordinatesToAddresses[(uint32(x) << 16) | y] = msg.sender;
        allBlockCoordinates.push((uint32(x) << 16) | y);
        
        // If the block is at the lowest layer...
        if (y == 0)
        {
            // The bet goes to the administrator
            addressBalances[administrator] += betAmount;
        }
        
        // If the block is NOT at the lowest layer...
        else
        {
            // Calculate the administrator fee
            uint256 adminFee = betAmount / adminFeeDivisor;
            
            // Calculate the bet amount minus the admin fee
            uint256 betAmountMinusAdminFee = betAmount - adminFee;
            
            // Add the money to the balances of the people below
            addressBalances[coordinatesToAddresses[(uint32(x  ) << 16) | (y-1)]] += betAmountMinusAdminFee / 2;
            addressBalances[coordinatesToAddresses[(uint32(x+1) << 16) | (y-1)]] += betAmountMinusAdminFee / 2;
            
            // Give the admin fee to the admin
            addressBalances[administrator] += adminFee;
        }
        
        // The new sender's balance must not have underflowed
        // (this verifies that the sender has enough balance to place the block)
        require(addressBalances[msg.sender] < (1 << 255));
        
        // Give the sender their chat message rights
        addressesToChatMessagesLeft[msg.sender] += uint32(1) << y;
        
        // Register the sender's total bets placed
        addressesToTotalWeiPlaced[msg.sender] += betAmount;
    }
    
    ////////////////////////////////////////////
    // Withdrawing balance
    function withdrawBalance(uint256 amountToWithdraw) external
    {
        require(amountToWithdraw != 0);
        
        // The user must have enough balance to withdraw
        require(addressBalances[msg.sender] >= amountToWithdraw);
        
        // Subtract the withdrawn amount from the user's balance
        addressBalances[msg.sender] -= amountToWithdraw;
        
        // Transfer the amount to the user's address
        // If the transfer() call fails an exception will be thrown,
        // and therefore the user's balance will be automatically restored
        msg.sender.transfer(amountToWithdraw);
    }
    
    /////////////////////////////////////////////
    // Chatbox data
    struct ChatMessage
    {
        address person;
        string message;
    }
    mapping(bytes32 => address) public usernamesToAddresses;
    mapping(address => bytes32) public addressesToUsernames;
    mapping(address => uint32) public addressesToChatMessagesLeft;
    ChatMessage[] public chatMessages;
    mapping(uint256 => bool) public censoredChatMessages;
    
    /////////////////////////////////////////////
    // Chatbox functions
    function registerUsername(bytes32 username) external
    {
        // The username must not already be token
        require(usernamesToAddresses[username] == 0);
        
        // The address must not already have a username
        require(addressesToUsernames[msg.sender] == 0);
        
        // Register the new username & address combination
        usernamesToAddresses[username] = msg.sender;
        addressesToUsernames[msg.sender] = username;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastMessageTime;
    mapping(address => uint256) public messageSpamScore;
    uint256 public constant COOLDOWN_PERIOD = 30; // 30 seconds between messages
    uint256 public constant SPAM_THRESHOLD = 5; // Accumulated spam score threshold
    
    function sendChatMessage(string message) external
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    {
        // The sender must have at least 1 chat message allowance
        require(addressesToChatMessagesLeft[msg.sender] >= 1);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Anti-spam mechanism: enforce cooldown period
        require(block.timestamp >= lastMessageTime[msg.sender] + COOLDOWN_PERIOD, "Message cooldown not met");
        
        // Calculate message frequency score based on timestamp
        uint256 timeSinceLastMessage = block.timestamp - lastMessageTime[msg.sender];
        
        // If messages are sent too quickly, increase spam score
        if (timeSinceLastMessage < COOLDOWN_PERIOD * 2) {
            messageSpamScore[msg.sender] += (COOLDOWN_PERIOD * 2 - timeSinceLastMessage) / 10;
        } else {
            // Decrease spam score over time (reward good behavior)
            if (messageSpamScore[msg.sender] > 0) {
                messageSpamScore[msg.sender] -= 1;
            }
        }
        
        // If spam score is too high, require additional cooldown
        if (messageSpamScore[msg.sender] >= SPAM_THRESHOLD) {
            require(block.timestamp >= lastMessageTime[msg.sender] + (COOLDOWN_PERIOD * messageSpamScore[msg.sender]), "Spam cooldown penalty active");
        }
        
        // Update last message timestamp
        lastMessageTime[msg.sender] = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        // Deduct 1 chat message allowence from the sender
        addressesToChatMessagesLeft[msg.sender]--;
        
        // Add the chat message
        chatMessages.push(ChatMessage(msg.sender, message));
    }
    
    function getTotalAmountOfChatMessages() public view returns (uint256)
    {
        return chatMessages.length;
    }
    
    function getChatMessageAtIndex(uint256 index) public view returns (address, bytes32, string)
    {
        address person = chatMessages[index].person;
        bytes32 username = addressesToUsernames[person];
        return (person, username, chatMessages[index].message);
    }
    
    // In case of chat messages with extremely rude or inappropriate
    // content, the administrator can censor a chat message.
    function censorChatMessage(uint256 chatMessageIndex) public
    {
        require(msg.sender == administrator);
        censoredChatMessages[chatMessageIndex] = true;
    }
    
    /////////////////////////////////////////////
    // Game ownership functions
    function transferOwnership(address newAdministrator) external
    {
        require(msg.sender == administrator);
        administrator = newAdministrator;
    }
    
    function setFeeDivisor(uint256 newFeeDivisor) external
    {
        require(msg.sender == administrator);
        require(newFeeDivisor >= 20); // The fee may never exceed 5%
        adminFeeDivisor = newFeeDivisor;
    }
}