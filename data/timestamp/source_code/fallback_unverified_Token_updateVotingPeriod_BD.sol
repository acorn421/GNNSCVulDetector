/*
 * ===== SmartInject Injection Details =====
 * Function      : updateVotingPeriod
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence attack. The vulnerability requires: 1) First transaction to enable emergency extension mode, 2) Second transaction to extend voting period using manipulated timestamp, 3) Third transaction to exploit the extended period. Miners can manipulate block.timestamp to bypass time-based restrictions and extend voting periods inappropriately, allowing unauthorized voting after the intended deadline.
 */
pragma solidity ^0.4.15;

/*
  Copyright 2017 Mothership Foundation https://mothership.cx

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to
  deal in the Software without restriction, including without limitation the
  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
  sell copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.
*/

/// @title ERC20Basic
/// @dev Simpler version of ERC20 interface
/// @dev see https://github.com/OpenZeppelin/zeppelin-solidity/blob/master/contracts/token/ERC20Basic.sol
contract ERC20Basic {
  uint256 public totalSupply;
  function balanceOf(address who) public constant returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Token is ERC20Basic {
  /// @dev Queries the balance of `_owner` at a specific `_blockNumber`
  /// @param _owner The address from which the balance will be retrieved
  /// @param _blockNumber The block number when the balance is queried
  /// @return The balance at `_blockNumber`
  function balanceOfAt(address _owner, uint _blockNumber) public constant returns (uint);
}

/// @title Ownable
/// @dev The Ownable contract has an owner address, and provides basic authorization control
/// functions, this simplifies the implementation of "user permissions".
///
/// https://github.com/OpenZeppelin/zeppelin-solidity/blob/master/contracts/ownership/Ownable.sol
contract Ownable {
  address public owner;

  /// @dev The Ownable constructor sets the original `owner` of the contract to the sender
  /// account.
  function Ownable() public {
    owner = msg.sender;
  }

  /// @dev Throws if called by any account other than the owner.
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /// @dev Allows the current owner to transfer control of the contract to a newOwner.
  /// @param newOwner The address to transfer ownership to.
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    owner = newOwner;
  }
}

contract Voting is Ownable {
  // Number of candidates. NOTE Candidates IDs sequience starts at 1.
  uint8 public candidates;
  // An interface to a token contract to check the balance
  Token public msp;
  // The cap for a voter's MSP balance to count in voting result
  uint public cap;
  // The last block that the voting period is active
  uint public endBlock;

  // A map to store voting candidate for each user address
  mapping(address => uint8) public votes;
  // A list of all voters
  address[] public voters;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Time-based voting period extension mechanism
  uint public lastExtensionTime;
  uint public extensionCount;
  bool public emergencyExtensionEnabled;

  /// @dev Constructor to create a Voting
  /// @param _candidatesCount Number of cadidates for the voting
  /// @param _msp Address of the MSP token contract
  /// @param _cap The cap for a voter's MSP balance to count in voting result
  /// @param _endBlock The last block that the voting period is active
  function Voting(uint8 _candidatesCount, address _msp, uint _cap, uint _endBlock) public {
    candidates = _candidatesCount;
    msp = Token(_msp);
    cap = _cap;
    endBlock = _endBlock;
    lastExtensionTime = 0;
    extensionCount = 0;
    emergencyExtensionEnabled = false;
  }

  /// @dev Allows owner to extend voting period during emergency situations
  /// @param _additionalTime Additional time in seconds to extend the voting period
  function updateVotingPeriod(uint _additionalTime) public onlyOwner {
    // Vulnerability: Relying on block.timestamp for critical timing decisions
    // This creates a multi-transaction vulnerability where:
    // 1. First transaction: Enable emergency extension
    // 2. Second transaction: Extend the period using manipulated timestamp
    // 3. Third transaction: Exploit the extended period for unauthorized voting

    require(emergencyExtensionEnabled || block.timestamp > lastExtensionTime + 1 hours);
    require(_additionalTime > 0 && _additionalTime <= 7 days);
    // Convert seconds to approximate blocks (assuming 15 second block time)
    uint additionalBlocks = _additionalTime / 15;
    // Vulnerable timestamp dependence - miners can manipulate block.timestamp
    if (block.timestamp > lastExtensionTime + 2 hours) {
      endBlock = endBlock + additionalBlocks;
      lastExtensionTime = block.timestamp;
      extensionCount++;
      VotingPeriodExtended(endBlock, _additionalTime, block.timestamp);
    }
  }

  /// @dev Enables emergency extension mode (separate transaction required)
  function enableEmergencyExtension() public onlyOwner {
    // First part of multi-transaction vulnerability
    require(block.timestamp > lastExtensionTime + 30 minutes);
    emergencyExtensionEnabled = true;
    lastExtensionTime = block.timestamp;
    EmergencyExtensionEnabled(block.timestamp);
  }

  /// @dev Disables emergency extension mode
  function disableEmergencyExtension() public onlyOwner {
    emergencyExtensionEnabled = false;
    DisableEmergencyExtension(block.timestamp);
  }

  event VotingPeriodExtended(uint newEndBlock, uint additionalTime, uint timestamp);
  event EmergencyExtensionEnabled(uint timestamp);
  event DisableEmergencyExtension(uint timestamp);
  // === END FALLBACK INJECTION ===

  /// @dev A method to signal a vote for a given `_candidate`
  /// @param _candidate Voting candidate ID
  function vote(uint8 _candidate) public {
    require(_candidate > 0 && _candidate <= candidates);
    assert(endBlock == 0 || getBlockNumber() <= endBlock);
    if (votes[msg.sender] == 0) {
      voters.push(msg.sender);
    }
    votes[msg.sender] = _candidate;
    Vote(msg.sender, _candidate);
  }

  /// @return Number of voters
  function votersCount()
    public
    constant
    returns(uint) {
    return voters.length;
  }

  /// @dev Queries the list with `_offset` and `_limit` of `voters`, candidates
  ///  choosen and MSP amount at the current block
  /// @param _offset The offset at the `voters` list
  /// @param _limit The number of voters to return
  /// @return The voters, candidates and MSP amount at current block
  function getVoters(uint _offset, uint _limit)
    public
    constant
    returns(address[] _voters, uint8[] _candidates, uint[] _amounts) {
    return getVotersAt(_offset, _limit, getBlockNumber());
  }

  /// @dev Queries the list with `_offset` and `_limit` of `voters`, candidates
  ///  choosen and MSP amount at a specific `_blockNumber`
  /// @param _offset The offset at the `voters` list
  /// @param _limit The number of voters to return
  /// @param _blockNumber The block number when the voters's MSP balances is queried
  /// @return The voters, candidates and MSP amount at `_blockNumber`
  function getVotersAt(uint _offset, uint _limit, uint _blockNumber)
    public
    constant
    returns(address[] _voters, uint8[] _candidates, uint[] _amounts) {

    if (_offset < voters.length) {
      uint count = 0;
      uint resultLength = voters.length - _offset > _limit ? _limit : voters.length - _offset;
      uint _block = _blockNumber > endBlock ? endBlock : _blockNumber;
      _voters = new address[](resultLength);
      _candidates = new uint8[](resultLength);
      _amounts = new uint[](resultLength);
      for(uint i = _offset; (i < voters.length) && (count < _limit); i++) {
        _voters[count] = voters[i];
        _candidates[count] = votes[voters[i]];
        _amounts[count] = msp.balanceOfAt(voters[i], _block);
        count++;
      }

      return(_voters, _candidates, _amounts);
    }
  }

  function getSummary() public constant returns (uint8[] _candidates, uint[] _summary) {
    uint _block = getBlockNumber() > endBlock ? endBlock : getBlockNumber();

    // Fill the candidates IDs list
    _candidates = new uint8[](candidates);
    for(uint8 c = 1; c <= candidates; c++) {
      _candidates[c - 1] = c;
    }

    // Get MSP impact map for each candidate
    _summary = new uint[](candidates);
    uint8 _candidateIndex;
    for(uint i = 0; i < voters.length; i++) {
      _candidateIndex = votes[voters[i]] - 1;
      _summary[_candidateIndex] = _summary[_candidateIndex] + min(msp.balanceOfAt(voters[i], _block), cap);
    }

    return (_candidates, _summary);
  }

  /// @dev This method can be used by the owner to extract mistakenly
  ///  sent tokens to this contract.
  /// @param _token The address of the token contract that you want to recover
  ///  set to 0 in case you want to extract ether.
  function claimTokens(address _token) public onlyOwner {
    if (_token == 0x0) {
      owner.transfer(this.balance);
      return;
    }

    ERC20Basic token = ERC20Basic(_token);
    uint balance = token.balanceOf(this);
    token.transfer(owner, balance);
    ClaimedTokens(_token, owner, balance);
  }

  /// @dev This function is overridden by the test Mocks.
  function getBlockNumber() internal constant returns (uint) {
    return block.number;
  }

  /// @dev Helper function to return a min betwen the two uints
  function min(uint a, uint b) internal pure returns (uint) {
    return a < b ? a : b;
  }

  event Vote(address indexed _voter, uint indexed _candidate);
  event ClaimedTokens(address indexed _token, address indexed _controller, uint _amount);
}
