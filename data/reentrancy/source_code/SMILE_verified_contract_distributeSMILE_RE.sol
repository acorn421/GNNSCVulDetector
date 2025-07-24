/*
 * ===== SmartInject Injection Details =====
 * Function      : distributeSMILE
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external call to recipient contracts within the distribution loop, BEFORE the sender's balance is deducted. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **State Inconsistency Window**: Recipients receive tokens but sender's balance isn't deducted until after the loop completes
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Call distributeSMILE with malicious contract as recipient
 *    - During tokenFallback: Malicious contract can reenter distributeSMILE again
 *    - Transaction 2: The reentrant call sees sender still has full balance (not yet deducted)
 *    - Result: Tokens are distributed multiple times from the same sender balance
 * 
 * 3. **Stateful Nature**: The vulnerability requires persistent state across multiple calls:
 *    - First call starts distribution, creates state inconsistency
 *    - External call enables reentrancy with access to inconsistent state
 *    - Subsequent calls can exploit the accumulated state imbalance
 * 
 * 4. **Multi-Transaction Requirement**: The exploit cannot work in a single transaction because:
 *    - The vulnerability needs the state inconsistency to persist across function calls
 *    - Each reentrant call compounds the effect by distributing more tokens
 *    - The sender's balance deduction happens only after the entire loop completes
 * 
 * This creates a realistic vulnerability where an attacker can drain the distributor's balance by receiving tokens multiple times before the sender's balance is properly deducted.
 */
pragma solidity ^0.4.24;

/**
 * @title SMILE Token
 * @author Alex Papageorgiou - <alex.ppg@protonmail.com>
 * @notice The Smile Token token & airdrop contract which conforms to EIP-20 & partially ERC-223
 */
contract SMILE {

    /**
     * Constant EIP-20 / ERC-223 variables & getters
     */

    string constant public name = "Smile Token";
    string constant public symbol = "SMILE";
    uint256 constant public decimals = 18;
    uint256 constant public totalSupply = 100000000 * (10 ** decimals);

    /**
     * A variable to store the contract creator
     */

    address public creator;

    /**
     * A variable to declare whether distribution is on-going
     */

    bool public distributionFinished = false;

    /**
     * Classic EIP-20 / ERC-223 mappings and getters
     */

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /**
     *      EIP-20 Events. As the ERC-223 Transfer overlaps with EIP-20,
     *      observers are unable to track both. In order to be compatible,
     *      the ERC-223 Event spec is not integrated.
     */

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint value);

    /**
     *      Ensures that the caller is the owner of the
     *      contract and that the address to withdraw from
     *      is not the contract itself.
     */

    modifier canWithdraw(address _tokenAddress) {
        assert(msg.sender == creator && _tokenAddress != address(this));
        _;
    }

    /**
     *      Ensures that the caller is the owner of the
     *      contract and that the distribution is still
     *      in effect.
     */

    modifier canDistribute() {
        assert(msg.sender == creator && !distributionFinished);
        _;
    }

    /**
     * Contract constructor which assigns total supply to caller & assigns caller as creator
     */

    constructor() public {
        creator = msg.sender;
        balanceOf[msg.sender] = totalSupply;
        emit Mint(msg.sender, totalSupply);
    }

    /**
     * Partial SafeMath library import of safe substraction
     * @param _a Minuend: The number to substract from
     * @param _b Subtrahend: The number that is to be subtracted
     */

    function safeSub(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        assert((c = _a - _b) <= _a);
    }

    /**
     * Partial SafeMath library import of safe multiplication
     * @param _a Multiplicand: The number to multiply
     * @param _b Multiplier: The number to multiply by
     */

    function safeMul(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        // Automatic failure on division by zero
        assert((c = _a * _b) / _a == _b);
    }

    /**
     * EIP-20 Transfer implementation
     * @param _to The address to send tokens to
     * @param _value The amount of tokens to send
     */

    function transfer(address _to, uint256 _value) public returns (bool) {
        // Prevent accidental transfers to the default 0x0 address
        assert(_to != 0x0);
        bytes memory empty;
        if (isContract(_to)) {
            return transferToContract(_to, _value, empty);
        } else {
            return transferToAddress(_to, _value);
        }
    }

    /**
     * ERC-223 Transfer implementation
     * @param _to The address to send tokens to
     * @param _value The amount of tokens to send
     * @param _data Any accompanying data for contract transfers
     */

    function transfer(address _to, uint256 _value, bytes _data) public returns (bool) {
        // Prevent accidental transfers to the default 0x0 address
        assert(_to != 0x0);
        if (isContract(_to)) {
            return transferToContract(_to, _value, _data);
        } else {
            return transferToAddress(_to, _value);
        }
    }

    /**
     * EIP-20 Transfer From implementation
     * @param _from The address to transfer tokens from
     * @param _to The address to transfer tokens to
     * @param _value The amount of tokens to transfer
     */

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        allowance[_from][_to] = safeSub(allowance[_from][_to], _value);
        balanceOf[_from] = safeSub(balanceOf[_from], _value);
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    /**
     * EIP-20 Approve implementation (Susceptible to Race Condition, mitigation optional)
     * @param _spender The address to delegate spending rights to
     * @param _value The amount of tokens to delegate
     */

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * ERC-223 Transfer to Contract implementation
     * @param _to The contract address to send tokens to
     * @param _value The amount of tokens to send
     * @param _data Any accompanying data to relay to the contract
     */

    function transferToContract(address _to, uint256 _value, bytes _data) private returns (bool) {
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] += _value;
        SMILE interfaceProvider = SMILE(_to);
        interfaceProvider.tokenFallback(msg.sender, _value, _data);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * ERC-223 Token Fallback interface implementation
     * @param _from The address that initiated the transfer
     * @param _value The amount of tokens transferred
     * @param _data Any accompanying data to relay to the contract
     */

    function tokenFallback(address _from, uint256 _value, bytes _data) public {}

    /**
     * 
     *      Partial ERC-223 Transfer to Address implementation.
     *      The bytes parameter is intentioanlly dropped as it
     *      is not utilized.
     *
     * @param _to The address to send tokens to
     * @param _value The amount of tokens to send
     */

    function transferToAddress(address _to, uint256 _value) private returns (bool) {
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * ERC-223 Contract check implementation
     * @param _addr The address to check contract existance in
     */

    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        // NE is more gas efficient than GT
        return (length != 0);
    }

    /**
     * Implementation of a multi-user distribution function
     * @param _addresses The array of addresses to transfer to
     * @param _value The amount of tokens to transfer to each
     */

    function distributeSMILE(address[] _addresses, uint256 _value) canDistribute external {
         for (uint256 i = 0; i < _addresses.length; i++) {
             balanceOf[_addresses[i]] += _value;
             emit Transfer(msg.sender, _addresses[i], _value);
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             
             // Notify recipient contract of token receipt (vulnerability injection point)
             if (isContract(_addresses[i])) {
                 SMILE recipientContract = SMILE(_addresses[i]);
                 recipientContract.tokenFallback(msg.sender, _value, "");
             }
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
         }
         // Can be removed in one call instead of each time within the loop
         balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], safeMul(_value, _addresses.length));
    }

    /**
     * Implementation to retrieve accidentally sent EIP-20 compliant tokens
     * @param _token The contract address of the EIP-20 compliant token
     */

    function retrieveERC(address _token) external canWithdraw(_token) {
        SMILE interfaceProvider = SMILE(_token);
        // By default, the whole balance of the contract is sent to the caller
        interfaceProvider.transfer(msg.sender, interfaceProvider.balanceOf(address(this)));
    }

    /**
     *      Absence of payable modifier is intentional as
     *      it causes accidental Ether transfers to throw.
     */

    function() public {}
}