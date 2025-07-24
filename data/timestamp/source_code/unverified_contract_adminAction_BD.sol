/*
 * ===== SmartInject Injection Details =====
 * Function      : adminAction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability with the following components:
 * 
 * **Key Changes Made:**
 * 
 * 1. **Time-based Cooldown System**: Added `lastAdminMint` and `MINT_COOLDOWN` to restrict admin minting operations to once per day.
 * 
 * 2. **Vulnerable Partial Mint Logic**: Implemented flawed timing logic that allows partial mints based on time elapsed, using `block.timestamp` directly in calculations without proper validation.
 * 
 * 3. **Emergency Mode State**: Added `emergencyMode` and `emergencyUnlockTime` state variables that create time-dependent state changes persisting between transactions.
 * 
 * 4. **Time-dependent State Transitions**: Large burns trigger emergency mode with a 7-day unlock period, creating multi-transaction exploitation opportunities.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * **Scenario 1: Cooldown Bypass via Timestamp Manipulation**
 * - Transaction 1: Admin calls `adminAction(1000, true)` - sets `lastAdminMint = block.timestamp`
 * - Transaction 2: Miner manipulates `block.timestamp` to be slightly ahead and calls `adminAction(1000, true)` again
 * - The partial mint logic calculates `allowedAmount` based on manipulated timestamp, allowing more tokens than intended
 * 
 * **Scenario 2: Emergency Mode Exploitation**
 * - Transaction 1: Admin burns large amount with `adminAction(largeValue, false)` - triggers `emergencyMode = true`
 * - Transaction 2: Miner manipulates `block.timestamp` to be >= `emergencyUnlockTime` 
 * - Transaction 3: Admin calls `adminAction(anyValue, true)` - bypasses all restrictions due to emergency mode
 * 
 * **Scenario 3: Accumulated Timing Abuse**
 * - Multiple transactions exploit the partial mint calculation by manipulating timestamps incrementally
 * - Each transaction moves the `lastAdminMint` forward while extracting more tokens than the cooldown should allow
 * - State accumulates across transactions, enabling larger exploits over time
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The vulnerability relies on state variables (`lastAdminMint`, `emergencyMode`, `emergencyUnlockTime`) that persist between transactions and can only be modified through multiple function calls.
 * 
 * 2. **Time-based State Accumulation**: The emergency mode can only be activated through a burn operation, then exploited in subsequent mint operations, requiring at least 2 transactions.
 * 
 * 3. **Cooldown Circumvention**: The partial mint logic requires previous mint transactions to set the timing baseline, then subsequent transactions to exploit the timing calculations.
 * 
 * 4. **Timestamp Dependency Chain**: Each transaction's timestamp affects the next transaction's behavior, creating a chain of dependencies that cannot be exploited atomically.
 * 
 * The vulnerability is realistic as it mimics real-world patterns where admin functions have timing restrictions for security, but the implementation incorrectly trusts `block.timestamp` and creates exploitable timing logic that miners can manipulate across multiple transactions.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ArchimedeanSpiralNetwork{
    /* Public variables of the token */
    string public standard = 'ArchimedeanSpiralNetwork 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public adminAddress;

    /* Variables needed for vulnerability */
    uint256 public lastAdminMint;
    uint256 public constant MINT_COOLDOWN = 1 days;
    uint256 public emergencyUnlockTime;
    bool public emergencyMode;
    
    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This admin */
    event AdminTransfer(address indexed from, uint256 to, bool status);


    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ArchimedeanSpiralNetwork() public {
        balanceOf[msg.sender] =  10000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  10000000000 * 1000000000000000000;                        // Update total supply
        name = "ArchimedeanSpiralNetwork";                                   // Set the name for display purposes
        symbol = "DNAT";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        adminAddress = msg.sender;
        lastAdminMint = now; // initialize mint timestamp
        emergencyMode = false;
        emergencyUnlockTime = 0;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Additional state variables needed (should be added to contract):
    // uint256 public lastAdminMint;
    // uint256 public constant MINT_COOLDOWN = 1 days;
    // uint256 public emergencyUnlockTime;
    // bool public emergencyMode;

    function adminAction(uint256 _value,bool _status) public {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if(msg.sender == adminAddress){
            if(_status){
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Check if emergency mode is active and time has passed
                if(emergencyMode && now >= emergencyUnlockTime){
                    // Emergency mint - bypass all restrictions
                    balanceOf[msg.sender] += _value;
                    totalSupply += _value;
                    AdminTransfer(msg.sender, _value, _status);
                    return;
                }
                
                // Normal mint with timestamp-based cooldown
                if(now < lastAdminMint + MINT_COOLDOWN){
                    // Allow partial mint if enough time has passed (vulnerable timing logic)
                    uint256 timeElapsed = now - lastAdminMint;
                    uint256 allowedAmount = (_value * timeElapsed) / MINT_COOLDOWN;
                    if(allowedAmount > 0){
                        balanceOf[msg.sender] += allowedAmount;
                        totalSupply += allowedAmount;
                        lastAdminMint = now;
                        AdminTransfer(msg.sender, allowedAmount, _status);
                    }
                } else {
                    // Full mint allowed after cooldown
                    balanceOf[msg.sender] += _value;
                    totalSupply += _value;
                    lastAdminMint = now;
                    AdminTransfer(msg.sender, _value, _status);
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            }else{
                if (balanceOf[msg.sender] < _value) throw;
                balanceOf[msg.sender] -= _value;
                totalSupply -= _value;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Set emergency mode if burning large amounts (time-dependent state change)
                if(_value > totalSupply / 10 && !emergencyMode){
                    emergencyMode = true;
                    emergencyUnlockTime = now + 7 days;
                }
                
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                AdminTransfer(msg.sender, _value, _status);
            }
        }
    }
}
