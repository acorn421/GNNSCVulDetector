/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending burn mechanism that requires multiple transactions to complete. The vulnerability is created by:
 * 
 * 1. **State Persistence**: Added `pendingBurns` and `pendingBurnTimestamp` mappings to track burn operations across transactions
 * 2. **Multi-Transaction Requirement**: First call initializes a pending burn with timestamp, second call (after delay) processes accumulated burns
 * 3. **External Call Before State Updates**: Added calls to `IBurnRegistry` before state modifications, creating reentrancy opportunity
 * 4. **Accumulated State**: Multiple pending burns can accumulate, and state checks use stale values during reentrancy
 * 
 * **Multi-Transaction Exploitation:**
 * - Transaction 1: Attacker calls `burnFrom()` to initiate pending burn, external registry call occurs
 * - Transaction 2: After delay, attacker calls `burnFrom()` again to process accumulated burns
 * - During the external call in Transaction 2, the registry contract can reenter and call `burnFrom()` again with stale state
 * - The reentrancy allows burning more tokens than intended because state hasn't been updated yet
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the accumulation of pending burns across multiple transactions
 * - Time delay prevents single-transaction exploitation
 * - State persistence between transactions is essential for the accumulated burn logic
 * - External registry calls provide reentrancy vector that depends on prior transaction state
 * 
 * This creates a realistic multi-transaction reentrancy where attackers must first establish pending burns, then exploit the external call during processing to manipulate accumulated state.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnRegistry {
    function notifyBurnInitiated(address from, address sender, uint256 value) external;
    function notifyBurnProcessed(address from, address sender, uint256 value) external;
}

contract BAHACAN {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Pending burns mapping and related state
    mapping(address => mapping(address => uint256)) public pendingBurns;
    mapping(address => mapping(address => uint256)) public pendingBurnTimestamp;
    address public burnRegistry;
    uint256 public burnDelay = 60; // Example: 60 second delay; adjust as appropriate

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
    event PendingBurn(address indexed from, address indexed sender, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function BAHACAN(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    function multiPartyTransfer(address[] _toAddresses, uint256[] _amounts) public {
        require(_toAddresses.length <= 255);
        require(_toAddresses.length == _amounts.length);

        for (uint8 i = 0; i < _toAddresses.length; i++) {
            transfer(_toAddresses[i], _amounts[i]);
        }
    }

    function multiPartyTransferFrom(address _from, address[] _toAddresses, uint256[] _amounts) public {
        require(_toAddresses.length <= 255);
        require(_toAddresses.length == _amounts.length);

        for (uint8 i = 0; i < _toAddresses.length; i++) {
            transferFrom(_from, _toAddresses[i], _amounts[i]);
        }
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending burn tracking for multi-transaction processing
        if (pendingBurns[_from][msg.sender] == 0) {
            pendingBurns[_from][msg.sender] = _value;
            pendingBurnTimestamp[_from][msg.sender] = block.timestamp;
            
            // Notify external burn registry before state changes
            if (burnRegistry != address(0)) {
                IBurnRegistry(burnRegistry).notifyBurnInitiated(_from, msg.sender, _value);
            }
            
            PendingBurn(_from, msg.sender, _value);
            return true;
        }
        
        // Process accumulated pending burns
        require(block.timestamp >= pendingBurnTimestamp[_from][msg.sender] + burnDelay);
        require(pendingBurns[_from][msg.sender] > 0);
        
        uint256 totalBurnValue = pendingBurns[_from][msg.sender] + _value;
        
        // External call to burn registry before state updates (vulnerability point)
        if (burnRegistry != address(0)) {
            IBurnRegistry(burnRegistry).notifyBurnProcessed(_from, msg.sender, totalBurnValue);
        }
        
        // State updates after external call (reentrancy vulnerability)
        balanceOf[_from] -= totalBurnValue;                         
        allowance[_from][msg.sender] -= totalBurnValue;             
        totalSupply -= totalBurnValue;                              
        
        // Clear pending burn
        pendingBurns[_from][msg.sender] = 0;
        pendingBurnTimestamp[_from][msg.sender] = 0;
        
        Burn(_from, totalBurnValue);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
}
