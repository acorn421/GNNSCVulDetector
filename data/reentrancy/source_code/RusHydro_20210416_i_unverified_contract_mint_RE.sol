/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient after state updates. The vulnerability requires multiple mint transactions to build exploitable state and allows the recipient contract to reenter during callbacks.
 * 
 * **Specific Changes Made:**
 * 1. Added external call using `_to.call(abi.encodeWithSignature("onTokenMint(uint256)", _value))` after state updates
 * 2. Added code length check to only call contracts (not EOAs) for realistic behavior  
 * 3. Placed the external call after `balances[_to]` and `totalSupply` modifications, violating Checks-Effects-Interactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner mints tokens to malicious contract A, which receives initial balance
 * 2. **Transaction 2**: Owner mints more tokens to contract A, triggering `onTokenMint` callback
 * 3. **During callback**: Contract A reenters mint function (if it controls owner) or other contract functions
 * 4. **State manipulation**: Contract A can exploit inconsistent state between its callback and main execution
 * 5. **Repeated calls**: Each mint builds upon previous state, amplifying the vulnerability impact
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction exploitation is prevented by the `onlyOwner` modifier limiting direct reentrancy
 * - Vulnerability requires building up token balances across multiple mint operations
 * - The exploit depends on accumulated state changes that persist between transactions
 * - Maximum impact requires multiple rounds of minting and callback manipulation
 * - The callback mechanism only becomes effective after the recipient has accumulated sufficient tokens from previous mints
 * 
 * **Realistic Attack Vector:**
 * - If the owner account is compromised or controlled by the attacker
 * - If the contract has multiple owners or delegation mechanisms
 * - If the callback can manipulate other contract state that affects subsequent mints
 * - Cross-contract interactions where the minted tokens are used in other protocols
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient about minting - vulnerable external call after state updates
        if (isContract(_to)) {
            bool success = _to.call(bytes4(keccak256("onTokenMint(uint256)")), _value);
            // Continue execution regardless of call result to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
}
