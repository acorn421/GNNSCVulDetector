/*
 * ===== SmartInject Injection Details =====
 * Function      : placeBlock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based consecutive block bonus system. The vulnerability allows miners to manipulate block timestamps across multiple transactions to:
 * 
 * 1. **Exploit Consecutive Block Discounts**: By manipulating timestamps in consecutive blocks, miners can accumulate consecutive block counts and receive significant betting discounts (up to 50% off).
 * 
 * 2. **Manipulate Time-Based Bonus Rewards**: The system gives bonus rewards to recently placed supporting blocks based on timestamp differences, which miners can exploit by controlling block times.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1-3 (Setup Phase):**
 * - Attacker places initial blocks at strategic positions
 * - Each placement updates `lastBlockTimestamp[attacker]` and `consecutiveBlockCount[attacker]`
 * - State variables accumulate across transactions
 * 
 * **Transaction 4-N (Exploitation Phase):**
 * - Miner manipulates `block.timestamp` to be within `bonusMultiplierPeriod` of previous placements
 * - Each subsequent placement triggers larger discounts due to accumulated `consecutiveBlockCount`
 * - Miner can place blocks at significantly reduced costs while receiving maximum bonuses
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: `consecutiveBlockCount` must build up over multiple transactions
 * 2. **Timing Windows**: The vulnerability requires establishing temporal relationships between blocks placed in different transactions
 * 3. **Supporting Block Dependencies**: Higher-layer blocks depend on lower-layer blocks placed in previous transactions
 * 4. **Bonus Calculation**: Time-based bonuses are calculated relative to timestamps from previous transactions
 * 
 * **Real-World Exploitation Scenario:**
 * - Miner observes pending transactions in mempool
 * - Manipulates timestamps across multiple blocks to create favorable timing windows
 * - Places multiple blocks in sequence with manipulated timestamps to maximize discounts and bonuses
 * - Each transaction builds upon state from previous transactions to compound the advantage
 * 
 * The vulnerability is realistic as it mimics common patterns in DeFi protocols that offer time-based incentives and bonuses.
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
    mapping(uint32 => address) public coordinatesToAddresses;
    uint32[] public allBlockCoordinates;
    
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
        uint32 coord = (uint32(1 << 15) << 16);
        coordinatesToAddresses[coord] = msg.sender;
        allBlockCoordinates.push(coord);
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
        return coordinatesToAddresses[(uint32(x) << 16) | uint32(y)] != 0;
    }
    
    function getTotalAmountOfBlocks() public view returns (uint256)
    {
        return allBlockCoordinates.length;
    }
    
    ////////////////////////////////////////////
    // Pyramid grid writing functions
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variables for time-based bonuses (these would be added to the contract)
    mapping(address => uint256) public lastBlockTimestamp;
    mapping(address => uint256) public consecutiveBlockCount;
    uint256 public bonusMultiplierPeriod = 300; // 5 minutes in seconds
    
    function placeBlock(uint16 x, uint16 y) external payable
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    {
        // You may only place a block on an empty spot
        require(!isThereABlockAtCoordinates(x, y));
        
        // Add the transaction amount to the person's balance
        addressBalances[msg.sender] += msg.value;
        
        // Calculate the required bet amount at the specified layer
        uint256 betAmount = getBetAmountAtLayer(y);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // VULNERABILITY: Time-based consecutive block bonus system
        // Check if this is a consecutive block placement within the bonus period
        if (lastBlockTimestamp[msg.sender] != 0 && 
            block.timestamp <= lastBlockTimestamp[msg.sender] + bonusMultiplierPeriod) {
            // Increment consecutive block count for rapid placements
            consecutiveBlockCount[msg.sender]++;
            
            // Apply discount based on consecutive placements and timing
            uint256 timeDelta = block.timestamp - lastBlockTimestamp[msg.sender];
            uint256 discountFactor = (bonusMultiplierPeriod - timeDelta) * consecutiveBlockCount[msg.sender];
            
            // Reduce bet amount by up to 50% for rapid consecutive placements
            if (discountFactor > 0) {
                uint256 discount = (betAmount * discountFactor) / (bonusMultiplierPeriod * 10);
                if (discount > betAmount / 2) {
                    discount = betAmount / 2;
                }
                betAmount -= discount;
            }
        } else {
            // Reset consecutive count if too much time has passed
            consecutiveBlockCount[msg.sender] = 1;
        }
        
        // Update the last block timestamp for this address
        lastBlockTimestamp[msg.sender] = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        // PREVENT UNDERFLOW/OVERFLOW BY BOUNDING x/y: Use int casts and checks
        // If the block is at the lowest layer...
        if (y == 0)
        {
            // There must be a block to the left or to the right of it
            // To avoid stack depth, store subresults to memory vars
            uint32 xSub1 = x >= 1 ? x-1 : 0;
            bool leftBlock = false;
            if (x >= 1) {
                leftBlock = isThereABlockAtCoordinates(xSub1, y);
            }
            bool rightBlock = isThereABlockAtCoordinates(x+1, y);
            require(leftBlock || rightBlock);
        }
        
        // If the block is NOT at the lowest layer...
        else
        {
            // There must be two existing blocks below it:
            // Store the two subresults to memory vars
            bool leftBelow = isThereABlockAtCoordinates(x  , y-1);
            bool rightBelow = isThereABlockAtCoordinates(x+1, y-1);
            require(leftBelow && rightBelow);
        }
        
        // Subtract the bet amount from the person's balance
        addressBalances[msg.sender] -= betAmount;
        
        // Place the block (store coordinates in a variable to reduce stack depth)
        uint32 newCoordinate = (uint32(x) << 16) | uint32(y);
        coordinatesToAddresses[newCoordinate] = msg.sender;
        allBlockCoordinates.push(newCoordinate);
        
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
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // VULNERABILITY: Time-based bonus rewards for block supporters
            // Check if the blocks below were placed recently for bonus rewards
            uint32 lowerLeftCoord = (uint32(x) << 16) | uint32(y-1);
            uint32 lowerRightCoord = (uint32(x+1) << 16) | uint32(y-1);
            address lowerLeft = coordinatesToAddresses[lowerLeftCoord];
            address lowerRight = coordinatesToAddresses[lowerRightCoord];
            
            uint256 leftBonus = 0;
            uint256 rightBonus = 0;
            
            // Give time-based bonuses to recently placed supporting blocks
            if (lastBlockTimestamp[lowerLeft] != 0 && 
                block.timestamp <= lastBlockTimestamp[lowerLeft] + bonusMultiplierPeriod) {
                uint256 leftTimeDelta = block.timestamp - lastBlockTimestamp[lowerLeft];
                leftBonus = (betAmountMinusAdminFee * (bonusMultiplierPeriod - leftTimeDelta)) / (bonusMultiplierPeriod * 4);
            }
            
            if (lastBlockTimestamp[lowerRight] != 0 && 
                block.timestamp <= lastBlockTimestamp[lowerRight] + bonusMultiplierPeriod) {
                uint256 rightTimeDelta = block.timestamp - lastBlockTimestamp[lowerRight];
                rightBonus = (betAmountMinusAdminFee * (bonusMultiplierPeriod - rightTimeDelta)) / (bonusMultiplierPeriod * 4);
            }
            
            // Distribute rewards with time-based bonuses
            addressBalances[lowerLeft] += (betAmountMinusAdminFee / 2) + leftBonus;
            addressBalances[lowerRight] += (betAmountMinusAdminFee / 2) + rightBonus;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            
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
