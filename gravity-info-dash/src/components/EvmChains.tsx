import { Button, ButtonGroup, Card, CardBody, CardTitle } from 'reactstrap';

interface Props {
  list: string[];
  current?: string;
  title: string;
  onSelect: (config: string) => void;
}

export const EvmChains: React.FC<Props> = ({
  list,
  onSelect,
  current,
  title
}) => {
  return (
    <Card className="ParametersCard" style={{ borderRadius: 8, padding: 20 }}>
      <CardBody>
        <CardTitle tag="h4">Evm chains</CardTitle>
        <ButtonGroup size="sm">
          {list.map((item) => (
            <Button
              outline
              color="primary"
              title={title}
              active={item === current}
              key={item}
              onClick={() => {
                onSelect(item);
              }}
            >
              {item}
            </Button>
          ))}
        </ButtonGroup>
      </CardBody>
    </Card>
  );
};
