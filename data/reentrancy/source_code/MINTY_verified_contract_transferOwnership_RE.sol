/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added persistent state tracking**: `pendingOwnershipTransfers` mapping persists between transactions
 * 2. **External call before state finalization**: Added callback to `IOwnershipReceiver` interface that occurs while ownership transfer is still pending
 * 3. **State-dependent completion logic**: Transfer completion depends on the `pendingOwnershipTransfers` flag that can be manipulated during the callback
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker deploys malicious contract implementing `IOwnershipReceiver`
 * - Current owner calls `transferOwnership(attackerContract)`
 * - `pendingOwnershipTransfers[attackerContract] = true`
 * - External call to `attackerContract.onOwnershipTransferred(currentOwner)`
 * - During callback, attacker can observe the pending state but cannot complete exploitation in same transaction
 * 
 * **Transaction 2 (State Manipulation):**
 * - Attacker's callback contract calls back into `transferOwnership` with a different address
 * - This creates overlapping pending transfers and state confusion
 * - The original transfer may complete while additional pending transfers remain active
 * 
 * **Transaction 3+ (Exploitation):**
 * - Attacker exploits the accumulated state inconsistencies
 * - Multiple pending transfers can exist simultaneously
 * - Race conditions between different pending transfers
 * - Ownership can be transferred multiple times due to persistent state manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires establishing persistent state (`pendingOwnershipTransfers`) in the first transaction
 * - The callback mechanism allows state observation but not immediate exploitation
 * - Full exploitation requires multiple transactions to create sufficient state confusion and race conditions
 * - The persistent mapping maintains the vulnerable state between transactions, enabling complex exploitation patterns that cannot be achieved atomically
 */
pragma solidity ^0.4.19;

contract IOwnershipReceiver {
    function onOwnershipTransferred(address previousOwner) public;
}

contract MINTY {
    string public name = 'MINTY';
    string public symbol = 'MINTY';
    uint8 public decimals = 18;
    uint public totalSupply = 10000000000000000000000000;
    uint public minted = totalSupply / 5;
    uint public minReward = 1000000000000000000;
    uint public fee = 700000000000000;
    uint public reducer = 1000;
    uint private randomNumber;
    address public owner;
    uint private ownerBalance;
    
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public successesOf;
    mapping (address => uint256) public failsOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) private pendingOwnershipTransfers;
    
    function transferOwnership(address newOwner) external onlyOwner {
        // Set pending transfer flag first
        pendingOwnershipTransfers[newOwner] = true;
        
        // External call to notify new owner before finalizing ownership
        if (isContract(newOwner)) {
            IOwnershipReceiver(newOwner).onOwnershipTransferred(owner);
        }
        
        // Only complete transfer if still pending (can be manipulated during callback)
        if (pendingOwnershipTransfers[newOwner]) {
            owner = newOwner;
            pendingOwnershipTransfers[newOwner] = false;
        }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function MINTY() public {
        owner = msg.sender;
        balanceOf[owner] = minted;
        balanceOf[this] = totalSupply - balanceOf[owner];
    }
    
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) external {
        _transfer(msg.sender, _to, _value);
    }
    
    /* Transfer tokens from other address */
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    /* Set allowance for other address */
    function approve(address _spender, uint256 _value) external returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    
    function withdrawEther() external onlyOwner {
        owner.transfer(ownerBalance);
        ownerBalance = 0;
    }
    
    function () external payable {
        if (msg.value == fee) {
            randomNumber += block.timestamp + uint(msg.sender);
            uint minedAtBlock = uint(block.blockhash(block.number - 1));
            uint minedHashRel = uint(sha256(minedAtBlock + randomNumber + uint(msg.sender))) % 10000000;
            uint balanceRel = balanceOf[msg.sender] * 1000 / minted;
            if (balanceRel >= 1) {
                if (balanceRel > 255) {
                    balanceRel = 255;
                }
                balanceRel = 2 ** balanceRel;
                balanceRel = 5000000 / balanceRel;
                balanceRel = 5000000 - balanceRel;
                if (minedHashRel < balanceRel) {
                    uint reward = minReward + minedHashRel * 1000 / reducer * 100000000000000;
                    _transfer(this, msg.sender, reward);
                    minted += reward;
                    successesOf[msg.sender]++;
                } else {
                    Transfer(this, msg.sender, 0);
                    failsOf[msg.sender]++;
                }
                ownerBalance += fee;
                reducer++;
            } else {
                revert();
            }
        } else {
            revert();
        }
    }
}
