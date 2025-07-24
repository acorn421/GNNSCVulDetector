/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding ERC777-style transfer hooks with persistent state tracking. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. Added `pendingTransfers` mapping to track transfer state across transactions
 * 2. Added `isContract()` check to identify contract recipients
 * 3. Introduced external call to `ITokenRecipient(_to).onTokenTransfer()` BEFORE state updates
 * 4. Added `PendingTransfer` struct to maintain state between transactions
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls `transfer()` to malicious contract, which triggers the external call hook before balance updates, setting up persistent state in `pendingTransfers`
 * - **Transaction 2**: Malicious contract can exploit the fact that `pendingTransfers` state persists and balances haven't been properly updated, allowing double-spending or other attacks
 * - **Transaction 3+**: Additional transactions can continue exploiting the accumulated state inconsistencies
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The `pendingTransfers` mapping persists state between transactions
 * 2. The external call in transaction 1 sets up conditions that can be exploited in subsequent transactions
 * 3. The `processed` flag creates a window where state is inconsistent across multiple calls
 * 4. Single-transaction reentrancy is limited by gas constraints and the specific state tracking mechanism
 * 
 * This creates a realistic vulnerability where attackers must coordinate multiple transactions to fully exploit the state management flaws, making it a genuine multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.11;

contract RepostiX   {

    string public name = "RepostiX";      //  token name
    string public symbol = "REPX";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 21000000000000000;
    address owner = 0x0;

    // Struct for pending transfer
    struct PendingTransfer {
        address to;
        uint256 value;
        bool processed;
    }
    // Mapping for pending transfers
    mapping(address => PendingTransfer) public pendingTransfers;

    // Declare ITokenRecipient as an external contract, not interface keyword (not supported in 0.4.11)
    contract ITokenRecipient {
        function onTokenTransfer(address from, uint256 value, bytes data) public;
    }

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    // Function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    // Use constructor keyword for Solidity >=0.4.22, but stay compatible with 0.4.11
    // (keep old-style constructor for 0.4.11)
    function RepostiX(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add support for ERC777-style transfer hooks to enhance token compatibility
        if (isContract(_to)) {
            // Record pending transfer for hook processing
            pendingTransfers[msg.sender] = PendingTransfer({
                to: _to,
                value: _value,
                processed: false
            });
            
            // Call recipient hook before state update (vulnerability: external call before state change)
            ITokenRecipient(_to).onTokenTransfer(msg.sender, _value, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark transfer as processed if it was pending
        if (pendingTransfers[msg.sender].processed == false && pendingTransfers[msg.sender].to == _to) {
            pendingTransfers[msg.sender].processed = true;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
