/*
 * ===== SmartInject Injection Details =====
 * Function      : placeBlock
 * Vulnerability : Reentrancy
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
 * **Vulnerability Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `msg.sender.call()` after all balance modifications but before the final balance validation
 * - The call is conditionally executed only if the sender has previously placed blocks (`addressesToTotalWeiPlaced[msg.sender] > 0`)
 * - The external call notifies about block placement and passes current game state parameters
 * - Used `require(success, "Reward notification failed")` to ensure the call succeeds
 * 
 * **2. Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 - Setup Phase:**
 * 1. Attacker deploys a malicious contract with a `onBlockPlaced` function
 * 2. Attacker calls `placeBlock()` once legitimately to set `addressesToTotalWeiPlaced[attacker] > 0`
 * 3. This establishes the precondition needed for the external call in future transactions
 * 
 * **Transaction 2+ - Exploitation Phase:**
 * 1. Attacker calls `placeBlock()` again with insufficient balance but enough to pass initial checks
 * 2. The function executes normally: balances are modified, block is placed, rewards distributed
 * 3. The external call `msg.sender.call()` is triggered since `addressesToTotalWeiPlaced[msg.sender] > 0`
 * 4. The malicious contract's `onBlockPlaced` function is called, which can:
 *    - Re-enter `placeBlock()` before the balance underflow check
 *    - Place multiple blocks while the original call is still pending
 *    - Exploit the fact that `addressesToTotalWeiPlaced` has already been incremented
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Dependency:** The vulnerability only triggers when `addressesToTotalWeiPlaced[msg.sender] > 0`, requiring at least one prior successful block placement.
 * 
 * **Accumulated Attack Surface:** Each successful block placement increases the attacker's historical bet amount, making subsequent attacks more profitable as the external call provides more context about the attacker's game history.
 * 
 * **Reentrancy Window:** The reentrancy opportunity exists between balance modifications and the final balance validation, but this window is only accessible after establishing the prerequisite state through previous transactions.
 * 
 * **Timing-Based Exploitation:** The attacker can accumulate balance through multiple small deposits across transactions, then exploit the reentrancy to place blocks worth more than their actual balance before the underflow check occurs.
 * 
 * **Multi-Call Strategy:** The attacker can use the first transaction to establish legitimacy, then use subsequent transactions to recursively call `placeBlock()` during the external call, bypassing balance checks through the reentrancy window.
 * 
 * This creates a realistic, stateful vulnerability that requires careful setup across multiple transactions and exploits the accumulated game state to enable the reentrancy attack.
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external reward contract about block placement
        // This provides achievements and bonus rewards for active players
        if (addressesToTotalWeiPlaced[msg.sender] > 0) {
            // Call external reward contract with current game state
            (bool success, ) = msg.sender.call(abi.encodeWithSignature("onBlockPlaced(uint16,uint16,uint256)", x, y, betAmount));
            require(success, "Reward notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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