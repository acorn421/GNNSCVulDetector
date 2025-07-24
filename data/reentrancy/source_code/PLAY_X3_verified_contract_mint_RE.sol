/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability enables the following multi-transaction exploitation pattern:
 * 
 * **Transaction 1 (Initial Attack Setup):**
 * - Attacker deploys a malicious contract at address A
 * - Owner calls mint(A, 1000) 
 * - External call to A.onTokenMint(1000) is made BEFORE state updates
 * - Malicious contract's onTokenMint function calls back into mint or other functions
 * - During reentrancy, balances[A] and totalSupply are still at old values
 * - Attacker can exploit this inconsistent state by calling transfer/transferFrom with old balance values
 * 
 * **Transaction 2+ (Exploitation Phase):**
 * - Attacker uses the tokens minted in Transaction 1 plus any additional tokens gained through reentrancy
 * - Due to the state inconsistency created in Transaction 1, the attacker may have more tokens than intended
 * - The accumulated state changes across transactions enable the exploitation
 * 
 * **Multi-Transaction Dependency:**
 * - The vulnerability cannot be exploited in a single transaction because the reentrancy occurs during the initial minting process
 * - The attacker must wait for the initial mint transaction to complete and establish the inconsistent state
 * - Subsequent transactions leverage this accumulated state to extract value
 * - The external call before state updates violates the Checks-Effects-Interactions pattern, creating a window for multi-transaction exploitation
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on persistent state (balances mapping, totalSupply)
 * - State changes from the initial reentrancy call affect future transactions
 * - The exploit effectiveness accumulates over multiple minting operations
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}

contract PLAY_X3 is Ownable {

    string public constant name = "\tPLAY_X3\t\t";
    string public constant symbol = "\tPLAYX3\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 10000000000000000000000000;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        /* Using extcodesize directly for code length check in pre-0.5.0 versions */
        uint256 size;
        assembly {
            size := extcodesize(_to)
        }
        if (size > 0) {
            _to.call(abi.encodeWithSignature("onTokenMint(uint256)", _value));
            // Continue regardless of call success to maintain backward compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) returns (bool success) {
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

    function approve(address _spender, uint _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    // IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT

    string inData_1 = "\tFIFA WORLD CUP 2018\t\t\t\t";

    function setData_1(string newData_1) public onlyOwner {
        inData_1 = newData_1;
    }

    function getData_1() public constant returns (string) {
        return inData_1;
    }

    string inData_2 = "\tMatch : 15.06.2018 20;00 (Bern Time)\t\t\t\t";

    function setData_2(string newData_2) public onlyOwner {
        inData_2 = newData_2;
    }

    function getData_2() public constant returns (string) {
        return inData_2;
    }

    string inData_3 = "\tPORTUGAL - SPAIN\t\t\t\t";

    function setData_3(string newData_3) public onlyOwner {
        inData_3 = newData_3;
    }

    function getData_3() public constant returns (string) {
        return inData_3;
    }

    string inData_4 = "\tCOTES [4.3017 ; 3.3799 ; 2.1201]\t\t\t\t";

    function setData_4(string newData_4) public onlyOwner {
        inData_4 = newData_4;
    }

    function getData_4() public constant returns (string) {
        return inData_4;
    }

    string inData_5 = "\tX\t\t\t\t";

    function setData_5(string newData_5) public onlyOwner {
        inData_5 = newData_5;
    }

    function getData_5() public constant returns (string) {
        return inData_5;
    }
}