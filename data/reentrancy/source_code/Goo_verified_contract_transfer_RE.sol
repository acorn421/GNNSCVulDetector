/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient after state updates. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker deploys a malicious contract implementing `onTokenReceived` that calls back into `transfer()`
 * 2. **Transaction 2**: When someone transfers tokens to the malicious contract, it triggers the hook, which can recursively call `transfer()` again before the first call completes
 * 
 * The vulnerability is stateful because:
 * - Balance updates persist between recursive calls
 * - Each recursive call sees the updated balances from previous calls
 * - The attacker can drain funds by repeatedly calling transfer with the same amount
 * 
 * Multi-transaction nature:
 * - Requires separate deployment transaction for malicious contract
 * - Exploitation happens during transfer transaction through recursive calls
 * - Each recursive call creates a new transaction context while maintaining state
 * - The vulnerability accumulates effect across multiple nested transaction calls
 * 
 * This mirrors real-world patterns where token contracts implement recipient notification hooks, making the vulnerability both realistic and practically exploitable.
 */
pragma solidity ^0.4.0;

// *NOT* GOO, just test ERC20 so i can verify EtherDelta works before launch.

interface ERC20 {
    function totalSupply() external constant returns (uint);
    function balanceOf(address tokenOwner) external constant returns (uint balance);
    function allowance(address tokenOwner, address spender) external constant returns (uint remaining);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint tokens) external returns (bool success);
    function transferFrom(address from, address to, uint tokens) external returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

contract Goo is ERC20 {
    string public constant name  = "ProofOfDev";
    string public constant symbol = "DevToken";
    uint8 public constant decimals = 0;
    uint256 private roughSupply;

    // Balances for each player
    mapping(address => uint256) private gooBalance;
    mapping(address => uint256) private lastGooSaveTime;
    mapping(address => mapping(address => uint256)) private allowed;

    // Constructor
    function Goo() public payable {
        roughSupply = 1;
        gooBalance[msg.sender] = 1;
        lastGooSaveTime[msg.sender] = block.timestamp;
    }

    function totalSupply() public constant returns(uint256) {
        return roughSupply; // Stored goo (rough supply as it ignores earned/unclaimed goo)
    }

    function balanceOf(address player) public constant returns(uint256) {
        return gooBalance[player] + balanceOfUnclaimedGoo(player);
    }

    function balanceOfUnclaimedGoo(address player) internal constant returns (uint256) {
        uint256 lastSave = lastGooSaveTime[player];
        if (lastSave > 0 && lastSave < block.timestamp) {
            return (1000 * (block.timestamp - lastSave)) / 100;
        }
        return 0;
    }

    function transfer(address recipient, uint256 amount) public returns (bool) {
        require(amount <= gooBalance[msg.sender]);
        gooBalance[msg.sender] -= amount;
        gooBalance[recipient] += amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Transfer notification hook - allows recipient to react to incoming transfers
        if (isContract(recipient)) {
            // Call recipient's onTokenReceived function if it exists
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
            recipient.call(selector, msg.sender, amount);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    function transferFrom(address player, address recipient, uint256 amount) public returns (bool) {
        require(amount <= allowed[player][msg.sender] && amount <= gooBalance[player]);
        gooBalance[player] -= amount;
        gooBalance[recipient] += amount;
        allowed[player][msg.sender] -= amount;
        emit Transfer(player, recipient, amount);
        return true;
    }

    function approve(address approvee, uint256 amount) public returns (bool){
        allowed[msg.sender][approvee] = amount;
        emit Approval(msg.sender, approvee, amount);
        return true;
    }

    function allowance(address player, address approvee) public constant returns(uint256){
        return allowed[player][approvee];
    }
    
    // Utility: detects if address is a contract (using extcodesize in assembly)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
