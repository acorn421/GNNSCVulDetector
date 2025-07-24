/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after balance updates
 * 2. Included a check `if(_to.code.length > 0)` to only call contracts, not EOAs
 * 3. Placed the external call after state modifications but before the Transfer event
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * This vulnerability is exploitable across multiple transactions through the following sequence:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract calls `approve()` to give itself allowance from victim's account
 * - Attacker contract calls `transferFrom()` to transfer tokens to itself
 * - During the external call, the attacker contract's `onTokenReceived()` function is triggered
 * - The attacker contract records the current state but doesn't immediately exploit (avoids single-transaction reentrancy)
 * - State after Transaction 1: Attacker has received tokens, allowances are updated
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker initiates another `transferFrom()` call using the same or different allowance
 * - The external call triggers `onTokenReceived()` again
 * - This time, the attacker contract uses the persistent state from Transaction 1 to call back into `transferFrom()`
 * - Since balances and allowances were already modified in previous transactions, the attacker can exploit inconsistent state
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence**: The vulnerability relies on the fact that `allowed` and `balances` mappings persist between transactions
 * 2. **Allowance Accumulation**: The attacker needs to build up sufficient allowances across multiple transactions
 * 3. **Reentrancy Window**: The external call creates a window where the contract state can be manipulated, but the full exploit requires leveraging state from previous transactions
 * 4. **Realistic Attack Vector**: Real-world reentrancy attacks often involve multiple transactions to set up the exploit conditions
 * 
 * **Stateful Nature:**
 * - The vulnerability exploits the persistent state of allowances and balances
 * - Each transaction modifies the global state that subsequent transactions can exploit
 * - The external call enables manipulation of these persistent state variables across transaction boundaries
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract RusHydro_20210416_i is Ownable {
    string public constant name = "\tRusHydro_20210416_i\t\t";
    string public constant symbol = "\tRUSHYI\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call to recipient contract after balance updates
            if (isContract(_to)) {
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    function isContract(address _addr) private view returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}
