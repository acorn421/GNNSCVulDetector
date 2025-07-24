/*
 * ===== SmartInject Injection Details =====
 * Function      : registerUsername
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through two mechanisms:
 * 
 * 1. **Premium Username Access Control**: Users can register premium usernames (starting with 0x00) only if they register during blocks with even timestamps. This creates a vulnerability where miners can manipulate block.timestamp to gain unfair access to premium usernames.
 * 
 * 2. **Registration Cooldown System**: Added a block.number-based cooldown system that prevents rapid username changes. This creates timestamp dependence as the cooldown can be manipulated by miners controlling block production timing.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1**: User places their first block in the game (calling placeBlock), establishing their addressesToTotalWeiPlaced[msg.sender] > 0 state.
 * 
 * **Transaction 2**: User attempts to register a premium username during an even timestamp block. A miner can:
 * - Manipulate block.timestamp to ensure it's even when the transaction is included
 * - Delay transaction inclusion until favorable timestamp conditions
 * - Frontrun legitimate users by controlling block timing
 * 
 * **Transaction 3+**: For username changes, the vulnerability allows miners to manipulate the apparent time passage between registrations by controlling block.number progression.
 * 
 * **Why Multi-Transaction is Required:**
 * 1. Users must first interact with the contract (place blocks) before registering premium usernames
 * 2. The cooldown system requires state persistence between registration attempts
 * 3. The vulnerability is only exploitable when miners can control the timing between these separate transactions
 * 4. Single-transaction exploitation is impossible because the prerequisite state (having placed blocks) must be established in prior transactions
 * 
 * This creates a realistic vulnerability where miners have unfair advantages in username registration timing, similar to MEV extraction opportunities seen in production DeFi protocols.
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
    
    /////////////////////////////////////////////
    // Address properties
    mapping(address => uint256) public addressesToTotalWeiPlaced;
    mapping(address => uint256) public addressBalances;
    
    ////////////////////////////////////////////
    // Game Constructor
    constructor() public
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
    
    // Added mapping to store last registration block for each address
    mapping(address => uint256) public addressesToLastRegistration;
    
    /////////////////////////////////////////////
    // Chatbox functions
    function registerUsername(bytes32 username) external
    {
        // The username must not already be token
        require(usernamesToAddresses[username] == 0);
        
        // The address must not already have a username
        require(addressesToUsernames[msg.sender] == 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Premium username registration window: usernames starting with 0x00 are reserved
        // for addresses that placed their first block in an "even" timestamp block
        if (username[0] == 0x00) {
            // Check if user has placed any blocks by checking total wei placed
            require(addressesToTotalWeiPlaced[msg.sender] > 0);
            
            // Get the timestamp of when user first participated (approximated by current block)
            // Users who started in "even" timestamp blocks get premium username access
            uint256 registrationTimestamp = block.timestamp;
            require(registrationTimestamp % 2 == 0);
        }
        
        // Standard username cooldown: prevent rapid username changes
        // Store the last registration timestamp for this address
        if (addressesToUsernames[msg.sender] != 0) {
            // If changing username, enforce 100 block cooldown period
            uint256 lastRegistrationBlock = addressesToLastRegistration[msg.sender];
            require(block.number >= lastRegistrationBlock + 100);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Register the new username & address combination
        usernamesToAddresses[username] = msg.sender;
        addressesToUsernames[msg.sender] = username;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Record the registration timestamp for future premium access checks
        addressesToLastRegistration[msg.sender] = block.number;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function sendChatMessage(string message) external
    {
        // The sender must have at least 1 chat message allowance
        require(addressesToChatMessagesLeft[msg.sender] >= 1);
        
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
