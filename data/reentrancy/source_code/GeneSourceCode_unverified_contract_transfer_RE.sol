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
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingTransfers` mapping to track incomplete transfers across transactions
 * 2. **External Callback Mechanism**: Added `ITransferReceiver(_to).onTransferReceived()` call after balance updates
 * 3. **Persistent State Window**: The `pendingTransfers` state persists between transactions when external calls fail
 * 4. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Initial transfer with failing callback creates pending state
 *    - Transaction 2: Attacker can exploit the persistent pending state
 *    - Transaction 3+: Continued exploitation of accumulated state inconsistencies
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys malicious contract that initially fails `onTransferReceived`
 * 2. **Trigger Phase (Transaction 2)**: Legitimate user transfers to attacker's contract, callback fails, `pendingTransfers` state persists
 * 3. **Exploitation Phase (Transaction 3+)**: Attacker's contract is updated to succeed callback but performs reentrancy, exploiting the accumulated pending state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent `pendingTransfers` state between transactions
 * - Cannot be exploited in single transaction due to the external call placement after balance updates
 * - Requires state accumulation across multiple failed/successful callback attempts
 * - The exploit window is created by the persistent state tracking mechanism
 * 
 * This creates a realistic scenario where protocol integrations with callback mechanisms introduce stateful reentrancy vulnerabilities that can only be exploited through carefully orchestrated multi-transaction sequences.
 */
pragma solidity ^0.4.11;

contract GeneSourceCode {

    string public name = "Gene Source Code Chain";      //  the GSC Chain token name
    string public symbol = "Gene";           //  the GSC Chain token symbol
    uint256 public decimals = 18;            //  the GSC Chain token digits

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // Added mapping for pendingTransfers
    mapping(address => mapping(address => uint256)) public pendingTransfers;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2000000000000000000000000000;
    address owner = 0x0;

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

    function GeneSourceCode(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    // Helper function to check if address is contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    // Interface declared outside contract per Solidity <0.5 requirement
    // Placing here for compatibility with 0.4.11
}

// Interface declaration MUST be outside the contract in 0.4.x
interface ITransferReceiver {
    function onTransferReceived(address _from, uint256 _value) external;
}

contract GeneSourceCodeExtended is GeneSourceCode {
    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add transfer tracking for multi-transaction exploitation
        if (pendingTransfers[msg.sender][_to] == 0) {
            pendingTransfers[msg.sender][_to] = block.number;
        }
        
        // Call external contract for transfer notification (vulnerable point)
        if (isContract(_to)) {
            // External call pattern for pre-0.5.0 Solidity
            ITransferReceiver(_to).onTransferReceived(msg.sender, _value);
            pendingTransfers[msg.sender][_to] = 0;
        } else {
            // Clear pending transfer for EOA
            pendingTransfers[msg.sender][_to] = 0;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }
}
