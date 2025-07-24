/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification mechanism that creates exploitable state inconsistencies. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. **Added State Variables** (assumed to be declared elsewhere):
 *    - `mapping(bytes32 => TransferData) pendingTransfers` - tracks transfer operations
 *    - `mapping(bytes32 => bool) processingTransfers` - prevents concurrent processing
 *    - `uint256 transferNonce` - ensures unique transfer IDs
 *    - `struct TransferData` - stores transfer details
 * 
 * 2. **Introduced External Call**: Added `TokenReceiver(_to).onTokenReceived()` call before all state updates are complete
 * 
 * 3. **Created Vulnerable State Sequence**: 
 *    - Sender balance updated first (optimistic update)
 *    - External call made with incomplete state
 *    - Recipient balance and allowance updated after external call
 * 
 * 4. **Multi-Transaction Exploitation Flow**:
 *    - **Transaction 1**: Legitimate transferFrom call begins, sender balance decremented, external call triggers
 *    - **Transaction 2**: During callback, attacker can call transferFrom again with same parameters while sender balance is decremented but recipient/allowance not yet updated
 *    - **Transaction 3**: Original transfer completes with manipulated state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the window between partial state updates across transaction boundaries
 * - Attacker needs to establish pending transfer state in one transaction, then exploit it in subsequent transactions
 * - The `processingTransfers` mapping creates persistent state that can be manipulated across multiple calls
 * - Real exploitation requires coordinated sequence of calls that span multiple transaction contexts
 * 
 * **Exploitation Scenario:**
 * 1. Alice approves Bob to transfer 100 tokens
 * 2. Bob calls transferFrom(Alice, MaliciousContract, 100)
 * 3. MaliciousContract.onTokenReceived() is called with Alice's balance already decremented
 * 4. MaliciousContract calls transferFrom(Alice, AttackerWallet, 100) again
 * 5. Second call succeeds because allowance not yet decremented from first call
 * 6. Bob receives 100 tokens, Attacker receives 100 tokens, but only 100 tokens were actually deducted from Alice
 * 
 * The vulnerability is stateful because it depends on the persistent state changes from previous transactions and requires multiple transaction calls to fully exploit the inconsistent state window.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-10-04
*/

pragma solidity ^0.4.26;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeMul(uint256 a, uint256 b) internal returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint256 a, uint256 b) internal returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }

    function assert(bool assertion) internal {
        if (!assertion) {
            revert();
        }
    }
}

contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value, bytes32 _transferId) public;
}

contract RFBToken is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public freezeOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /* New reentrancy variables */
    struct TransferData {
        address from;
        address to;
        uint256 value;
        address spender;
        bool processed;
    }
    mapping(bytes32 => TransferData) public pendingTransfers;
    mapping(bytes32 => bool) public processingTransfers;
    uint256 public transferNonce;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimalUnits);
        // Update total supply
        balanceOf[msg.sender] = totalSupply;
        // Give the creator all initial tokens
        name = tokenName;
        // Set the name for display purposes
        symbol = tokenSymbol;
        // Set the symbol for display purposes
        decimals = decimalUnits;
        // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Helper function to check if _addr is a contract */
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();
        // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();
        // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);
        // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
    public returns (bool success) {
        if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();
        // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();
        // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();
        // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();
        // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Create unique transfer ID for multi-step processing
        bytes32 transferId = keccak256(abi.encodePacked(_from, _to, _value, block.timestamp, transferNonce++));
        
        // Mark transfer as processing to prevent double-execution
        if (processingTransfers[transferId]) revert();
        processingTransfers[transferId] = true;
        
        // Store pending transfer data for delayed execution
        pendingTransfers[transferId] = TransferData({
            from: _from,
            to: _to,
            value: _value,
            spender: msg.sender,
            processed: false
        });
        
        // Optimistically update sender balance first (vulnerable state)
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        
        // Notify recipient contract about incoming transfer (external call before full state update)
        if (isContract(_to)) {
            // No 'try/catch' in Solidity 0.4.x; need to use low-level call
            // We call TokenReceiver(_to).onTokenReceived and revert changes if it fails
            bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256,bytes32)"));
            bool callSuccess = _to.call.gas(msg.gas)(abi.encodeWithSelector(sig, _from, _value, transferId));
            if (!callSuccess) {
                balanceOf[_from] = SafeMath.safeAdd(balanceOf[_from], _value);
                processingTransfers[transferId] = false;
                return false;
            }
        }
        
        // Complete the transfer in vulnerable state (after external call)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark transfer as completed
        pendingTransfers[transferId].processed = true;
        processingTransfers[transferId] = false;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply, _value);
        // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);
        // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
        // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
}
