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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Added a callback mechanism to the destination address after balance updates but before the Transfer event. This creates a multi-transaction reentrancy vulnerability where:
 * 
 * 1. **Transaction 1**: An attacker deploys a malicious contract that implements ITokenReceiver interface
 * 2. **Transaction 2**: The attacker calls transferFrom with their malicious contract as dst
 * 3. **During Transaction 2**: The malicious contract's onTokenReceived callback is invoked while the WLAMB contract is in an inconsistent state (balances updated but Transfer event not yet emitted)
 * 4. **Reentrancy Attack**: The malicious contract can re-enter transferFrom or other functions during the callback, potentially manipulating allowances or performing additional transfers while the original transfer is still in progress
 * 
 * The vulnerability is stateful because:
 * - The attacker must first deploy and configure the malicious contract (persistent state)
 * - The balanceOf and allowance mappings are modified across multiple transactions
 * - The callback creates a window where the contract state is inconsistent, enabling exploitation in subsequent calls
 * 
 * This is multi-transaction because the attacker needs:
 * 1. Deploy malicious contract
 * 2. Set up allowances/balances
 * 3. Trigger the vulnerable transferFrom
 * 4. Exploit during the callback with additional function calls
 * 
 * The callback placement after balance updates but before completion creates the perfect reentrancy window for cross-function attacks.
 */
pragma solidity ^0.4.18;

interface IERC20 {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);
}

// Added missing interface declaration
interface ITokenReceiver {
    function onTokenReceived(address src, uint wad) external;
}

contract WLAMB {
    string public name     = "Childhood of Zuckerberg Goat, Wrapped LAMB";
    string public symbol   = "WLAMB";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;
    
    IERC20 LAMB;
    
    uint public totalSupply;
    
    constructor(address _originLAMB) public {
        require(_originLAMB != address(0), "origin lamb address can not be zero address");
        LAMB = IERC20(_originLAMB);
    }
    
    function deposit(uint amount) public {
        require(LAMB.transferFrom(msg.sender, address(this), amount), "transfer from error");
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        emit Deposit(msg.sender, amount);
    }
    
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        totalSupply -= wad;
        LAMB.transfer(msg.sender, wad);
        emit Withdrawal(msg.sender, wad);
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Token transfer callback - vulnerable to reentrancy
        if (isContract(dst)) {
            ITokenReceiver(dst).onTokenReceived(src, wad);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(src, dst, wad);

        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
