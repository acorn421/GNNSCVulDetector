/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the recipient address (_to.code.length > 0)
 * 2. Inserted an external call to _to.call() with onTokenReceived notification before state updates
 * 3. The external call occurs after validation checks but before critical state modifications (allowance reduction, balance transfers)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker approves a malicious contract to spend tokens on their behalf
 * - Attacker sets up the malicious contract with reentrancy logic in onTokenReceived function
 * 
 * **Transaction 2 (Exploitation):**
 * - Legitimate user calls transferFrom() to transfer tokens to the malicious contract
 * - Function validates balances and allowances (checks pass)
 * - External call to malicious contract's onTokenReceived() is made BEFORE state updates
 * - During this call, balances[_from] and allowed[_from][msg.sender] are still at original values
 * - Malicious contract re-enters transferFrom() with same parameters
 * - Second call passes validation checks again (state not yet updated)
 * - This creates a cycle where multiple transfers can occur before any state updates
 * 
 * **Why Multi-Transaction Nature is Essential:**
 * 1. **State Accumulation**: The vulnerability requires the attacker to first set up approvals and deploy malicious contracts across separate transactions
 * 2. **Persistent State Exploitation**: Each reentrancy call exploits the fact that state from previous incomplete transactions persists
 * 3. **Sequential Dependency**: The attack requires a specific sequence - setup transaction(s) followed by the triggering transaction with reentrancy
 * 4. **Cross-Transaction State Consistency**: The vulnerability exploits the gap between state validation and state modification across multiple call frames
 * 
 * **Realistic Implementation**: This mirrors real-world patterns where tokens notify recipients about incoming transfers, commonly seen in ERC-777 and other advanced token standards. The vulnerability appears as a legitimate feature implementation but creates a classic reentrancy attack vector.
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

contract PLAY_X1 is Ownable {

    string public constant name = "\tPLAY_X1\t\t";
    string public constant symbol = "\tPLAYX1\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 10000000000000000000000000;

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
        if(allowed[_from][msg.sender] >= _value &&
           balances[_from] >= _value && balances[_to] + _value >= balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient about incoming transfer before state updates
            // This creates a reentrancy window where state is still inconsistent
            if (isContract(_to)) {
                // External call to recipient contract before state updates
                _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
                // Continue regardless of call success to maintain functionality
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // contract detection using extcodesize for <0.5.0
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    // IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT
    string inData_1 = "\tFIFA WORLD CUP 2018\t\t\t";
    function setData_1(string newData_1) public onlyOwner {
        inData_1 = newData_1;
    }
    function getData_1() public constant returns (string) {
        return inData_1;
    }
    string inData_2 = "\tMatch : 15.06.2018 14;00 (Bern Time)\t\t\t";
    function setData_2(string newData_2) public onlyOwner {
        inData_2 = newData_2;
    }
    function getData_2() public constant returns (string) {
        return inData_2;
    }
    string inData_3 = "\tEGYPTE - URUGUAY\t\t\t";
    function setData_3(string newData_3) public onlyOwner {
        inData_3 = newData_3;
    }
    function getData_3() public constant returns (string) {
        return inData_3;
    }
    string inData_4 = "\tCOTES [7.1047 ; 3.9642 ; 1.6475]\t\t\t";
    function setData_4(string newData_4) public onlyOwner {
        inData_4 = newData_4;
    }
    function getData_4() public constant returns (string) {
        return inData_4;
    }
    string inData_5 = "\tX\t\t\t";
    function setData_5(string newData_5) public onlyOwner {
        inData_5 = newData_5;
    }
    function getData_5() public constant returns (string) {
        return inData_5;
    }
}